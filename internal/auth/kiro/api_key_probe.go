// Package kiro provides authentication functionality for AWS CodeWhisperer (Kiro) API.
// This file implements region discovery for Kiro API key credentials.
package kiro

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
)

// apiKeyProbeRegions is the ordered set of data-plane regions probed when a Kiro
// API key is imported without an explicit region.
var apiKeyProbeRegions = []string{"us-east-1", "eu-central-1"}

// APIKeyProber discovers which region a Kiro API key serves.
//
// A key is bound to its profile server-side, but the data plane is regional, so a
// key only answers in its home region. Unlike an OAuth credential — whose region
// is re-derived from the profile ARN on every refresh — an API key never
// re-probes, so a wrong region is permanent: the credential imports cleanly and
// then fails every request. The region is therefore discovered at import instead
// of assumed.
type APIKeyProber struct {
	httpClient *http.Client
}

// NewAPIKeyProber creates a prober that honours the configured proxy settings.
func NewAPIKeyProber(cfg *config.Config) *APIKeyProber {
	client := &http.Client{Timeout: 30 * time.Second}
	if cfg != nil {
		client = util.SetProxy(&cfg.SDKConfig, client)
	}
	return &APIKeyProber{httpClient: client}
}

// APIKeyProbeResult reports the outcome of a successful probe.
type APIKeyProbeResult struct {
	// Region is the region that accepted the key.
	Region string
	// SubscriptionTitle is the plan reported by the upstream, when present.
	SubscriptionTitle string
}

// candidateRegions returns the regions to probe. An explicit region narrows the
// probe to that single region, validating the operator's claim rather than
// silently overriding it.
func candidateRegions(explicitRegion string) []string {
	if trimmed := strings.TrimSpace(explicitRegion); trimmed != "" && !strings.EqualFold(trimmed, "auto") {
		return []string{trimmed}
	}
	if env := strings.TrimSpace(os.Getenv("KIRO_PROFILE_REGIONS")); env != "" {
		out := make([]string, 0, 4)
		for _, region := range strings.Split(env, ",") {
			if region = strings.TrimSpace(region); region != "" {
				out = append(out, region)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return apiKeyProbeRegions
}

// ResolveAPIKeyRegion finds the region that accepts the key.
//
// The returned bool reports whether the failure looks retryable: false means
// every probe was an authentication rejection, so the key genuinely does not
// serve those regions; true means at least one probe failed for a transient
// reason and must not be reported as a bad key. Errors never quote the key.
func (p *APIKeyProber) ResolveAPIKeyRegion(ctx context.Context, apiKey, explicitRegion string) (*APIKeyProbeResult, bool, error) {
	if p == nil || p.httpClient == nil {
		return nil, true, fmt.Errorf("api key prober is not initialized")
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, false, fmt.Errorf("api key is empty")
	}

	regions := candidateRegions(explicitRegion)
	rejected := make([]string, 0, len(regions))
	retryable := false

	for _, region := range regions {
		result, authFailure, err := p.probe(ctx, apiKey, region)
		if err == nil {
			return result, false, nil
		}
		if !authFailure {
			retryable = true
		}
		rejected = append(rejected, region)
		if ctx != nil && ctx.Err() != nil {
			return nil, true, fmt.Errorf("api key region probe canceled")
		}
	}

	return nil, retryable, fmt.Errorf("api key is not usable in the probed regions (%s)", strings.Join(rejected, ", "))
}

// probe issues one getUsageLimits call against a region. It reports whether the
// failure was an authentication rejection so the caller can tell a bad key from a
// transient upstream problem.
func (p *APIKeyProber) probe(ctx context.Context, apiKey, region string) (*APIKeyProbeResult, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	url := buildURL(GetKiroAPIEndpoint(region), pathGetUsageLimits, map[string]string{
		"origin":       "AI_EDITOR",
		"resourceType": "AGENTIC_REQUEST",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create probe request: %w", err)
	}
	setRuntimeHeaders(req, apiKey, GenerateAccountKey(apiKey))
	applyTokenType(req, AuthMethodAPIKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("probe request failed for region %s", region)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusOK {
		return &APIKeyProbeResult{Region: region}, false, nil
	}
	authFailure := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	// The response body can echo the credential, so only the status is reported.
	return nil, authFailure, fmt.Errorf("region %s rejected the key (status %d)", region, resp.StatusCode)
}
