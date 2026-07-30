package kiro

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Supported Kiro credential auth methods after normalization.
const (
	// AuthMethodBuilderID is an AWS Builder ID SSO OIDC credential.
	AuthMethodBuilderID = "builder-id"
	// AuthMethodIDC is an AWS IAM Identity Center credential; it requires a start URL.
	AuthMethodIDC = "idc"
	// AuthMethodSocial is a Kiro social (Google/GitHub) credential refreshed by Kiro's endpoint.
	AuthMethodSocial = "social"
	// AuthMethodImported is a Kiro IDE credential whose exact origin is unknown.
	AuthMethodImported = "imported"
	// AuthMethodAPIKey is a Kiro API key. It carries no refresh token: the key
	// itself is the bearer credential and never rotates, so it is excluded from
	// the refresh paths and must be sent with the API_KEY token type.
	AuthMethodAPIKey = "api_key"
)

// CredentialImport is the normalized, validated form of an externally supplied
// Kiro credential. It is the single boundary between foreign payload shapes
// (kiro-go camelCase, Kiro IDE files, snake_case auth files) and the flat
// snake_case auth records CLIProxyAPI persists.
type CredentialImport struct {
	AccessToken  string
	RefreshToken string
	// APIKey is a Kiro API key. It is mutually exclusive with the OAuth fields:
	// when set, the credential authenticates with the key instead of a rotating
	// access token.
	APIKey       string
	ProfileArn   string
	ExpiresAt    time.Time
	AuthMethod   string
	Provider     string
	ClientID     string
	ClientSecret string
	ClientIDHash string
	Region       string
	StartURL     string
	Email        string
}

// credentialFields is the intermediate view of a foreign payload. Keys are read
// through alias lists so camelCase and snake_case inputs behave identically.
type credentialFields map[string]any

// NormalizeCredentialPayload parses one JSON document into normalized Kiro
// credentials. It accepts a single credential object, an array of credentials,
// a kiro-go style {"accounts":[...]} export, and a {"credentials":{...}} wrapper.
// Every returned credential is validated and safe to persist; errors never echo
// secret values.
func NormalizeCredentialPayload(data []byte) ([]*CredentialImport, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, fmt.Errorf("credential payload is empty")
	}

	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("credential payload is not valid JSON")
	}

	objects, err := collectCredentialObjects(root, 0)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		return nil, fmt.Errorf("credential payload contains no credential objects")
	}

	out := make([]*CredentialImport, 0, len(objects))
	for i, fields := range objects {
		credential, errNormalize := normalizeCredentialFields(fields)
		if errNormalize != nil {
			if len(objects) == 1 {
				return nil, errNormalize
			}
			return nil, fmt.Errorf("credential #%d: %w", i+1, errNormalize)
		}
		out = append(out, credential)
	}
	return out, nil
}

// collectCredentialObjects flattens the accepted container shapes into a list of
// credential objects. depth bounds recursion so a hostile payload cannot force
// unbounded nesting.
func collectCredentialObjects(node any, depth int) ([]credentialFields, error) {
	if depth > 4 {
		return nil, fmt.Errorf("credential payload is nested too deeply")
	}
	switch typed := node.(type) {
	case []any:
		var out []credentialFields
		for _, item := range typed {
			nested, err := collectCredentialObjects(item, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
		}
		return out, nil
	case map[string]any:
		if accounts, ok := typed["accounts"]; ok {
			return collectCredentialObjects(accounts, depth+1)
		}
		if credentials, ok := typed["credentials"]; ok {
			// A kiro-go account wraps its secrets in "credentials" but keeps
			// identity fields (email, nickname) alongside it; merge both so the
			// email survives the import.
			nested, err := collectCredentialObjects(credentials, depth+1)
			if err != nil {
				return nil, err
			}
			for _, fields := range nested {
				for _, key := range []string{"email", "nickname", "provider", "region", "profileArn", "profile_arn", "startUrl", "start_url"} {
					if _, exists := fields[key]; exists {
						continue
					}
					if value, ok := typed[key]; ok {
						fields[key] = value
					}
				}
			}
			return nested, nil
		}
		return []credentialFields{credentialFields(typed)}, nil
	default:
		return nil, fmt.Errorf("credential payload must be an object or array of objects")
	}
}

// normalizeCredentialFields validates one credential object and converts it to
// the canonical representation.
func normalizeCredentialFields(fields credentialFields) (*CredentialImport, error) {
	credential := &CredentialImport{
		AccessToken:  strings.TrimSpace(importStringField(fields, "accessToken", "access_token")),
		RefreshToken: strings.TrimSpace(importStringField(fields, "refreshToken", "refresh_token")),
		ProfileArn:   strings.TrimSpace(importStringField(fields, "profileArn", "profile_arn")),
		ClientID:     strings.TrimSpace(importStringField(fields, "clientId", "client_id")),
		ClientSecret: strings.TrimSpace(importStringField(fields, "clientSecret", "client_secret")),
		ClientIDHash: strings.TrimSpace(importStringField(fields, "clientIdHash", "client_id_hash")),
		Region:       strings.TrimSpace(importStringField(fields, "region", "authRegion", "auth_region")),
		StartURL:     strings.TrimSpace(importStringField(fields, "startUrl", "start_url")),
		Email:        strings.TrimSpace(importStringField(fields, "email", "nickname")),
		Provider:     strings.TrimSpace(importStringField(fields, "provider")),
		APIKey:       strings.TrimSpace(importStringField(fields, "kiroApiKey", "kiro_api_key", "apiKey", "api_key")),
	}

	if credential.Email == "" {
		credential.Email = ExtractEmailFromJWT(credential.AccessToken)
	}

	// The auth method is resolved before the per-method requirements are checked,
	// so a payload missing its key is told which field it is missing rather than
	// being reported against whichever check happens to run first.
	authMethod, err := NormalizeCredentialAuthMethod(importStringField(fields, "authMethod", "auth_method"), credential)
	if err != nil {
		return nil, err
	}
	credential.AuthMethod = authMethod

	// An API key's region is discovered by probing, so a blank value must stay
	// blank here: defaulting it would narrow the probe to one region and pin a
	// wrong region permanently, since an API key never re-probes after import.
	if credential.Region == "" && credential.AuthMethod != AuthMethodAPIKey {
		credential.Region = DefaultKiroRegion
	}

	expiresAt, err := parseCredentialExpiry(importAnyField(fields, "expiresAt", "expires_at"))
	if err != nil {
		return nil, err
	}
	credential.ExpiresAt = expiresAt

	if credential.Provider == "" {
		credential.Provider = defaultProviderForAuthMethod(credential.AuthMethod)
	}

	if err := validateCredential(credential); err != nil {
		return nil, err
	}
	return credential, nil
}

// NormalizeCredentialAuthMethod maps the many spellings of an auth method onto
// the four methods the Kiro runtime can refresh. When the input is absent the
// method is inferred from the credential shape: IDC/Builder ID credentials carry
// OIDC client credentials, everything else is treated as an imported Kiro IDE
// credential.
//
// The builder-id/idc distinction is deliberate rather than a rename: idc refresh
// targets a region-specific OIDC endpoint and needs a start URL, while
// builder-id refreshes against us-east-1 with client credentials only.
func NormalizeCredentialAuthMethod(raw string, credential *CredentialImport) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.ReplaceAll(normalized, "_", "-")

	switch normalized {
	case AuthMethodIDC, "enterprise", "identity-center", "iam-idc":
		return AuthMethodIDC, nil
	case AuthMethodBuilderID, "builderid", "aws", "builder":
		return AuthMethodBuilderID, nil
	case AuthMethodSocial, "google", "github", "cookie":
		return AuthMethodSocial, nil
	case AuthMethodImported:
		return AuthMethodImported, nil
	case "api-key", "apikey":
		// Both spellings arrive from foreign payloads; the underscore form is
		// canonical because kiro-go persists authMethod as "api_key".
		return AuthMethodAPIKey, nil
	case "":
		return inferCredentialAuthMethod(credential), nil
	default:
		return "", fmt.Errorf("unsupported auth method %q", normalized)
	}
}

// inferCredentialAuthMethod guesses the auth method for payloads that omit it.
func inferCredentialAuthMethod(credential *CredentialImport) string {
	if credential == nil {
		return AuthMethodImported
	}
	// A payload carrying a key but no refresh token can only be an API key.
	if credential.APIKey != "" && credential.RefreshToken == "" {
		return AuthMethodAPIKey
	}
	if credential.StartURL != "" {
		return AuthMethodIDC
	}
	if credential.ClientID != "" && credential.ClientSecret != "" {
		return AuthMethodBuilderID
	}
	if credential.ClientIDHash != "" {
		return AuthMethodIDC
	}
	return AuthMethodImported
}

// defaultProviderForAuthMethod supplies the provider label used for file naming
// when the payload does not carry one.
func defaultProviderForAuthMethod(authMethod string) string {
	switch authMethod {
	case AuthMethodIDC, AuthMethodBuilderID:
		return "AWS"
	case AuthMethodAPIKey:
		return "ApiKey"
	default:
		return AuthMethodImported
	}
}

// validateCredential enforces the per-method requirements of the refresh paths in
// KiroAuthenticator.Refresh, so an unusable credential is rejected at import
// instead of failing later during a request.
func validateCredential(credential *CredentialImport) error {
	switch credential.AuthMethod {
	case AuthMethodIDC:
		if credential.RefreshToken == "" {
			return fmt.Errorf("refresh token is required")
		}
		if credential.ClientID == "" || credential.ClientSecret == "" {
			return fmt.Errorf("idc credentials require clientId and clientSecret")
		}
		if credential.StartURL == "" {
			return fmt.Errorf("idc credentials require startUrl")
		}
	case AuthMethodBuilderID:
		if credential.RefreshToken == "" {
			return fmt.Errorf("refresh token is required")
		}
		if credential.ClientID == "" || credential.ClientSecret == "" {
			return fmt.Errorf("builder-id credentials require clientId and clientSecret")
		}
	case AuthMethodSocial, AuthMethodImported:
		// Social and imported credentials refresh through Kiro's own endpoint,
		// which needs only the refresh token.
		if credential.RefreshToken == "" {
			return fmt.Errorf("refresh token is required")
		}
	case AuthMethodAPIKey:
		// An API key never rotates, so a refresh token is meaningless here and a
		// missing key leaves nothing to authenticate with.
		if credential.APIKey == "" {
			return fmt.Errorf("api_key credentials require kiroApiKey")
		}
	default:
		return fmt.Errorf("unsupported auth method %q", credential.AuthMethod)
	}
	return nil
}

// parseCredentialExpiry accepts RFC3339 strings, Unix seconds and Unix
// milliseconds, because kiro-go stores seconds internally, its account export
// uses milliseconds, and CLIProxyAPI auth files use RFC3339.
func parseCredentialExpiry(raw any) (time.Time, error) {
	switch value := raw.(type) {
	case nil:
		return time.Time{}, nil
	case string:
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return time.Time{}, nil
		}
		if parsed, err := time.Parse(time.RFC3339, trimmed); err == nil {
			return parsed, nil
		}
		numeric, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("expiresAt is not an RFC3339 timestamp or Unix epoch value")
		}
		return epochToTime(numeric), nil
	case float64:
		return epochToTime(int64(value)), nil
	case json.Number:
		numeric, err := value.Int64()
		if err != nil {
			return time.Time{}, fmt.Errorf("expiresAt is not a valid Unix epoch value")
		}
		return epochToTime(numeric), nil
	default:
		return time.Time{}, fmt.Errorf("expiresAt has an unsupported type")
	}
}

// epochToTime converts a Unix epoch value to a time, distinguishing seconds from
// milliseconds by magnitude. The threshold corresponds to year ~2286 in seconds,
// so any larger value must be milliseconds.
func epochToTime(value int64) time.Time {
	if value <= 0 {
		return time.Time{}
	}
	const millisecondThreshold = 1e11
	if value >= millisecondThreshold {
		return time.UnixMilli(value)
	}
	return time.Unix(value, 0)
}

// FileName returns the auth file name for the credential, matching the naming
// convention used by the CLI login flows in sdk/auth/kiro.go.
func (c *CredentialImport) FileName() string {
	label := c.Label()
	idPart := SanitizeEmailForFilename(c.Email)
	if idPart == "" && c.AuthMethod == AuthMethodIDC {
		idPart = SanitizeEmailForFilename(ExtractIDCIdentifier(c.StartURL))
	}
	if idPart == "" && c.ProfileArn != "" {
		parts := strings.Split(c.ProfileArn, "/")
		idPart = SanitizeEmailForFilename(parts[len(parts)-1])
	}
	if idPart == "" {
		idPart = SanitizeEmailForFilename(c.ClientID)
	}
	if idPart == "" {
		idPart = fmt.Sprintf("%05d", time.Now().UnixNano()%100000)
	}
	return fmt.Sprintf("%s-%s.json", label, idPart)
}

// Label returns the auth record label for the credential.
func (c *CredentialImport) Label() string {
	switch c.AuthMethod {
	case AuthMethodIDC:
		return "kiro-idc"
	case AuthMethodBuilderID:
		return "kiro-aws"
	case AuthMethodAPIKey:
		return "kiro-apikey"
	default:
		provider := SanitizeEmailForFilename(strings.ToLower(strings.TrimSpace(c.Provider)))
		if provider == "" {
			provider = AuthMethodImported
		}
		return "kiro-" + provider
	}
}

// Metadata renders the credential as the flat snake_case auth metadata the Kiro
// executor and refresh paths read.
func (c *CredentialImport) Metadata() map[string]any {
	if c.AuthMethod == AuthMethodAPIKey {
		// The key is mirrored into access_token so the executor's existing
		// credential lookup keeps working, and api_key marks the request paths
		// that must send the API_KEY token type. No refresh token is stored:
		// an API key never rotates, and a blank expiry keeps it out of the
		// expiry-driven refresh schedule.
		metadata := map[string]any{
			"type":         "kiro",
			"access_token": c.APIKey,
			"api_key":      c.APIKey,
			"auth_method":  c.AuthMethod,
			"provider":     c.Provider,
			"expires_at":   "",
			"last_refresh": time.Now().UTC().Format(time.RFC3339),
		}
		for key, value := range map[string]string{
			"email":       c.Email,
			"region":      c.Region,
			"api_region":  c.Region,
			"profile_arn": c.ProfileArn,
		} {
			if value != "" {
				metadata[key] = value
			}
		}
		return metadata
	}

	metadata := map[string]any{
		"type":          "kiro",
		"access_token":  c.AccessToken,
		"refresh_token": c.RefreshToken,
		"profile_arn":   c.ProfileArn,
		"expires_at":    c.ExpiresAtString(),
		"auth_method":   c.AuthMethod,
		"provider":      c.Provider,
		"email":         c.Email,
		"last_refresh":  time.Now().UTC().Format(time.RFC3339),
	}
	for key, value := range map[string]string{
		"client_id":      c.ClientID,
		"client_secret":  c.ClientSecret,
		"client_id_hash": c.ClientIDHash,
		"region":         c.Region,
		"start_url":      c.StartURL,
	} {
		if value != "" {
			metadata[key] = value
		}
	}
	return metadata
}

// Attributes renders the non-secret attributes stored alongside the credential.
func (c *CredentialImport) Attributes(source string) map[string]string {
	attributes := map[string]string{
		"source":      strings.TrimSpace(source),
		"profile_arn": c.ProfileArn,
		"email":       c.Email,
		"region":      c.Region,
	}
	if c.StartURL != "" {
		attributes["start_url"] = c.StartURL
	}
	return attributes
}

// ExpiresAtString renders the expiry as RFC3339. An unknown expiry is reported
// as already expired so the refresh manager revalidates the credential before
// its first use instead of trusting an arbitrary window.
func (c *CredentialImport) ExpiresAtString() string {
	if c.ExpiresAt.IsZero() {
		return time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	}
	return c.ExpiresAt.UTC().Format(time.RFC3339)
}

// ToTokenData converts the credential into the shared Kiro token structure used
// by the refresh and profile-resolution helpers.
//
// For an API key the key itself takes the access-token slot, because the key is
// the bearer credential every downstream helper expects to find there.
func (c *CredentialImport) ToTokenData() *KiroTokenData {
	accessToken := c.AccessToken
	if c.AuthMethod == AuthMethodAPIKey {
		accessToken = c.APIKey
	}
	return &KiroTokenData{
		AccessToken:  accessToken,
		RefreshToken: c.RefreshToken,
		ProfileArn:   c.ProfileArn,
		ExpiresAt:    c.ExpiresAtString(),
		AuthMethod:   c.AuthMethod,
		Provider:     c.Provider,
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		ClientIDHash: c.ClientIDHash,
		Email:        c.Email,
		StartURL:     c.StartURL,
		Region:       c.Region,
	}
}

// importAnyField returns the first present value among the given aliases.
func importAnyField(fields map[string]any, names ...string) any {
	for _, name := range names {
		if raw, ok := fields[name]; ok && raw != nil {
			return raw
		}
	}
	return nil
}
