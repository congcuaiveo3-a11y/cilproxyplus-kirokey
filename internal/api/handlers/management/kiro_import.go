package management

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// maxKiroImportBodyBytes bounds the credential payload a management client may
// upload. Kiro credential documents are small; a larger body is a mistake or an
// attempt to exhaust memory.
const maxKiroImportBodyBytes = 1 << 20

// kiroAPIKeyRefreshGate keeps API key credentials out of the refresh schedule.
// The key is the credential: there is no refresh token to exchange, so any
// refresh attempt can only fail and mark the credential unavailable.
const kiroAPIKeyRefreshGate = 100 * 365 * 24 * time.Hour

// kiroImportRefresh exchanges an imported credential's refresh token so a dead
// token is rejected before it is stored. It is a variable so tests can verify
// the import path without reaching AWS.
var kiroImportRefresh = func(ctx context.Context, cfg *config.Config, record *coreauth.Auth) (*coreauth.Auth, error) {
	return sdkAuth.NewKiroAuthenticator().Refresh(ctx, cfg, record)
}

// ImportKiroCredentials accepts Kiro credentials from an external source and
// persists them as CLIProxyAPI auth records.
//
// It accepts a single credential object, an array, a kiro-go style
// {"accounts":[...]} export, and a {"credentials":{...}} wrapper, in camelCase or
// snake_case. Payloads are normalized and validated by
// kiroauth.NormalizeCredentialPayload before anything is written, so an
// unrefreshable credential is rejected here rather than failing later on a
// request. Responses never echo tokens or client secrets.
//
// After import CLIProxyAPI becomes the refresh-token owner for these
// credentials. Keeping the source system refreshing the same refresh token would
// let each side rotate the other's token out from under it, so the source
// credential should be disabled once the import succeeds.
func (h *Handler) ImportKiroCredentials(c *gin.Context) {
	if h == nil || h.cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "config unavailable"})
		return
	}
	if strings.TrimSpace(h.cfg.AuthDir) == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth directory not configured"})
		return
	}

	data, err := readKiroImportPayload(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}

	credentials, err := kiroauth.NormalizeCredentialPayload(data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_credential", "message": err.Error()})
		return
	}

	ctx := context.Background()
	if reqCtx := c.Request.Context(); reqCtx != nil {
		ctx = reqCtx
	}
	ctx = PopulateAuthContext(ctx, c)

	imported := make([]gin.H, 0, len(credentials))
	failures := make([]gin.H, 0)
	storeFailed := false

	for i, credential := range credentials {
		// An API key is bound to one data-plane region and never re-probes once
		// stored, so a wrong region would be permanent. Discover it here instead,
		// which also validates the key before anything is written to disk.
		if credential.AuthMethod == kiroauth.AuthMethodAPIKey {
			result, retryable, errProbe := kiroauth.NewAPIKeyProber(h.cfg).ResolveAPIKeyRegion(ctx, credential.APIKey, credential.Region)
			if errProbe != nil {
				status := http.StatusBadRequest
				code := "invalid_credential"
				if retryable {
					// A transient upstream failure is not a bad key.
					status = http.StatusBadGateway
					code = "probe_failed"
				}
				c.JSON(status, gin.H{"error": code, "message": errProbe.Error()})
				return
			}
			credential.Region = result.Region
		}

		record := kiroCredentialAuthRecord(credential, "kiro-credential-import")

		// Every other method authenticates through a refresh token, so the token is
		// exchanged once here. A dead or mistyped token is otherwise accepted
		// silently and only surfaces as a failed request later, which looks like a
		// broken proxy rather than a bad credential. The refreshed record is what
		// gets stored, so the credential also arrives with a live access token and a
		// real expiry instead of the placeholder from the payload.
		if credential.AuthMethod != kiroauth.AuthMethodAPIKey {
			refreshed, errRefresh := kiroImportRefresh(ctx, h.cfg, record)
			if errRefresh != nil {
				// The upstream error can echo the token, so only a fixed message is
				// returned and the detail stays in the log.
				log.WithError(errRefresh).Warn("kiro: rejected an imported credential that failed to refresh")
				failures = append(failures, gin.H{
					"index":   i + 1,
					"message": "credential was rejected upstream: the refresh token is invalid or expired",
				})
				continue
			}
			record = refreshed
		}

		savedPath, errSave := h.saveTokenRecord(ctx, record)
		if errSave != nil {
			// errSave can quote the auth file path but never the credential body.
			log.WithError(errSave).Warn("failed to save imported kiro credential")
			storeFailed = true
			failures = append(failures, gin.H{
				"index":   i + 1,
				"message": "failed to save credential",
			})
			continue
		}
		imported = append(imported, gin.H{
			"auth-file":   savedPath,
			"auth_method": credential.AuthMethod,
			"provider":    credential.Provider,
			"email":       credential.Email,
			"region":      credential.Region,
			"expires_at":  credential.ExpiresAtString(),
		})
	}

	if len(imported) == 0 {
		// Nothing stored: a rejected credential is the caller's problem, while a
		// failing store is ours. Reporting both as 500 would tell an operator to
		// look at the server when the token is what needs replacing.
		status := http.StatusBadRequest
		code := "invalid_credential"
		if storeFailed {
			status = http.StatusInternalServerError
			code = "save_failed"
		}
		c.JSON(status, gin.H{
			"error":  code,
			"failed": failures,
		})
		return
	}

	response := gin.H{
		"status":   "ok",
		"imported": imported,
		"count":    len(imported),
	}
	if len(failures) > 0 {
		response["failed"] = failures
	}
	c.JSON(http.StatusOK, response)
}

// readKiroImportPayload reads the credential document from either a multipart
// file upload or the raw request body, bounded by maxKiroImportBodyBytes.
func readKiroImportPayload(c *gin.Context) ([]byte, error) {
	if fileHeader, err := c.FormFile("file"); err == nil {
		if fileHeader.Size > maxKiroImportBodyBytes {
			return nil, fmt.Errorf("credential file is too large")
		}
		file, errOpen := fileHeader.Open()
		if errOpen != nil {
			return nil, fmt.Errorf("failed to read credential file")
		}
		defer func() {
			if errClose := file.Close(); errClose != nil {
				log.WithError(errClose).Debug("failed to close uploaded kiro credential file")
			}
		}()
		data, errRead := io.ReadAll(io.LimitReader(file, maxKiroImportBodyBytes))
		if errRead != nil {
			return nil, fmt.Errorf("failed to read credential file")
		}
		return data, nil
	}

	if c.Request == nil || c.Request.Body == nil {
		return nil, fmt.Errorf("request body is required")
	}
	data, err := io.ReadAll(io.LimitReader(c.Request.Body, maxKiroImportBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body")
	}
	if len(data) > maxKiroImportBodyBytes {
		return nil, fmt.Errorf("credential payload is too large")
	}
	return data, nil
}

// kiroCredentialAuthRecord builds the auth record persisted for one normalized
// credential, mirroring the record shape produced by the Kiro CLI login flows.
func kiroCredentialAuthRecord(credential *kiroauth.CredentialImport, source string) *coreauth.Auth {
	fileName := credential.FileName()
	now := time.Now()

	record := &coreauth.Auth{
		ID:         fileName,
		Provider:   "kiro",
		FileName:   fileName,
		Label:      credential.Label(),
		Status:     coreauth.StatusActive,
		CreatedAt:  now,
		UpdatedAt:  now,
		Metadata:   credential.Metadata(),
		Attributes: credential.Attributes(source),
	}

	// An API key never expires and has nothing to rotate, so it gets a far-future
	// refresh gate instead of an expiry-derived one. Deriving the gate from the
	// (absent) expiry would schedule an immediate refresh that can only fail.
	if credential.AuthMethod == kiroauth.AuthMethodAPIKey {
		record.NextRefreshAfter = now.Add(kiroAPIKeyRefreshGate)
		return record
	}

	expiresAt := kiroauth.ParseExpiresAt(credential.ExpiresAtString())
	record.NextRefreshAfter = expiresAt.Add(-20 * time.Minute)
	return record
}
