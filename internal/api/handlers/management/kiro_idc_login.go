package management

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	kiroauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/kiro"
	log "github.com/sirupsen/logrus"
)

// startKiroIDCDeviceLogin runs the AWS IAM Identity Center device-code flow for a
// management client. Unlike Builder ID, IDC registers its OIDC client against the
// tenant's own region and start URL, and the same pair must be persisted because
// the refresh endpoint is region-specific.
func (h *Handler) startKiroIDCDeviceLogin(c *gin.Context, state string) {
	startURL, err := normalizeKiroStartURL(c.Query("start_url"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_start_url", "message": err.Error()})
		return
	}
	region, err := normalizeKiroRegion(c.Query("region"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_region", "message": err.Error()})
		return
	}

	ctx := context.Background()
	RegisterOAuthSession(state, "kiro")

	go func() {
		ssoClient := kiroauth.NewSSOOIDCClient(h.cfg)

		regResp, errRegister := ssoClient.RegisterClientWithRegion(ctx, region)
		if errRegister != nil {
			log.WithError(errRegister).Error("kiro idc: failed to register client")
			SetOAuthSessionError(state, "Failed to register client")
			return
		}

		authResp, errAuth := ssoClient.StartDeviceAuthorizationWithIDC(ctx, regResp.ClientID, regResp.ClientSecret, startURL, region)
		if errAuth != nil {
			log.WithError(errAuth).Error("kiro idc: failed to start device authorization")
			SetOAuthSessionError(state, "Failed to start device authorization")
			return
		}

		// "|" separates the fields because verification URLs contain ":".
		SetOAuthSessionError(state, "device_code|"+authResp.VerificationURIComplete+"|"+authResp.UserCode)

		interval := 5 * time.Second
		if authResp.Interval > 0 {
			interval = time.Duration(authResp.Interval) * time.Second
		}
		deadline := time.Now().Add(time.Duration(authResp.ExpiresIn) * time.Second)

		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				SetOAuthSessionError(state, "Authorization cancelled")
				return
			case <-time.After(interval):
			}

			tokenResp, errToken := ssoClient.CreateTokenWithRegion(ctx, regResp.ClientID, regResp.ClientSecret, authResp.DeviceCode, region)
			if errToken != nil {
				if errors.Is(errToken, kiroauth.ErrAuthorizationPending) {
					continue
				}
				if errors.Is(errToken, kiroauth.ErrSlowDown) {
					interval += 5 * time.Second
					continue
				}
				log.WithError(errToken).Error("kiro idc: token creation failed")
				SetOAuthSessionError(state, "Token creation failed")
				return
			}

			credential := &kiroauth.CredentialImport{
				AccessToken:  tokenResp.AccessToken,
				RefreshToken: tokenResp.RefreshToken,
				ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
				AuthMethod:   kiroauth.AuthMethodIDC,
				Provider:     "Enterprise",
				ClientID:     regResp.ClientID,
				ClientSecret: regResp.ClientSecret,
				Region:       region,
				StartURL:     startURL,
				Email:        kiroauth.ExtractEmailFromJWT(tokenResp.AccessToken),
			}
			if credential.Email == "" {
				credential.Email = ssoClient.FetchUserEmail(ctx, tokenResp.AccessToken)
			}
			credential.ProfileArn = ssoClient.FetchProfileArn(ctx, tokenResp.AccessToken, regResp.ClientID, tokenResp.RefreshToken)

			record := kiroCredentialAuthRecord(credential, "kiro-idc-device")
			savedPath, errSave := h.saveOAuthTokenRecord(ctx, state, "kiro", record)
			if errors.Is(errSave, errOAuthSessionNotPending) {
				return
			}
			if errSave != nil {
				log.WithError(errSave).Error("kiro idc: failed to save authentication tokens")
				SetOAuthSessionError(state, "Failed to save authentication tokens")
				return
			}

			log.Infof("kiro idc: authentication successful, token saved to %s", savedPath)
			CompleteOAuthSession(state)
			return
		}

		SetOAuthSessionError(state, "Authorization timed out")
	}()

	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"state":     state,
		"method":    "device_code",
		"region":    region,
		"start_url": startURL,
	})
}

// The authorization-code variants of Builder ID and IDC are intentionally not
// exposed here: they need a browser callback listener on the machine running the
// browser, which a remote management client cannot provide. The device flows
// produce the same credential types without a callback listener.

// normalizeKiroStartURL validates an IAM Identity Center start URL. Only https
// URLs without credentials, query or fragment are accepted, because the value is
// persisted and later sent to AWS as the OIDC issuer.
func normalizeKiroStartURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("start_url is required for the idc method")
	}
	if len(trimmed) > 512 {
		return "", fmt.Errorf("start_url is too long")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" {
		return "", fmt.Errorf("start_url is not a valid absolute URL")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", fmt.Errorf("start_url must use https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("start_url must not contain credentials, a query or a fragment")
	}
	if parsed.Hostname() == "" {
		return "", fmt.Errorf("start_url is missing a host")
	}
	return strings.TrimRight(trimmed, "/"), nil
}

// normalizeKiroRegion validates an AWS region label. The value is interpolated
// into the OIDC endpoint host, so only the conservative AWS region shape is
// accepted.
func normalizeKiroRegion(raw string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(raw))
	if trimmed == "" {
		return kiroauth.DefaultKiroRegion, nil
	}
	if len(trimmed) > 32 {
		return "", fmt.Errorf("region is too long")
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return "", fmt.Errorf("region contains invalid characters")
		}
	}
	return trimmed, nil
}
