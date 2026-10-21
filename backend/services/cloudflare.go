package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// The Cloudflare client is deliberately small: the base URL is fixed, so a
// stored zone can never be pointed at another host, and every call carries
// its own timeout so one slow zone cannot stall the poller for the others.
// A var only so tests can point it at a local server.
var CloudflareAPI = "https://api.cloudflare.com/client/v4"

var cloudflareHTTP = &http.Client{Timeout: 30 * time.Second}

// Zone and account IDs are 32 hex characters. Checking the shape before they
// are put into a path is what keeps a pasted value from rewriting the URL.
var cloudflareIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func ValidCloudflareID(id string) bool { return cloudflareIDPattern.MatchString(id) }

type CloudflareClient struct {
	Token string
}

func NewCloudflareClient(token string) *CloudflareClient {
	return &CloudflareClient{Token: token}
}

type cloudflareEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfMessage     `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// CloudflareError keeps the HTTP status next to Cloudflare's own message, so
// callers can tell "this token may not read notifications" (403) from "the
// API is down" without parsing text.
type CloudflareError struct {
	Status  int
	Message string
}

func (e *CloudflareError) Error() string { return e.Message }

func (c *CloudflareClient) rest(ctx context.Context, path string, query url.Values, out interface{}) error {
	u := CloudflareAPI + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := cloudflareHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	var env cloudflareEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return &CloudflareError{Status: resp.StatusCode, Message: fmt.Sprintf("cloudflare returned %d", resp.StatusCode)}
	}
	if !env.Success || resp.StatusCode >= 300 {
		return &CloudflareError{Status: resp.StatusCode, Message: joinCFMessages(env.Errors, resp.StatusCode)}
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

func joinCFMessages(errs []cfMessage, status int) string {
	if len(errs) == 0 {
		return fmt.Sprintf("cloudflare returned %d", status)
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		parts = append(parts, fmt.Sprintf("%s (code %d)", e.Message, e.Code))
	}
	return strings.Join(parts, "; ")
}

// VerifyToken checks the token is active. A user token answers on
// /user/tokens/verify; an account-owned token only answers on the account's
// own endpoint, so that one is tried when the first refuses.
func (c *CloudflareClient) VerifyToken(ctx context.Context, accountID string) error {
	var res struct {
		Status string `json:"status"`
	}
	err := c.rest(ctx, "/user/tokens/verify", nil, &res)
	if err != nil && accountID != "" {
		err = c.rest(ctx, "/accounts/"+accountID+"/tokens/verify", nil, &res)
	}
	if err != nil {
		return err
	}
	if res.Status != "" && res.Status != "active" {
		return fmt.Errorf("token status is %q", res.Status)
	}
	return nil
}

type CloudflareZoneInfo struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Paused bool   `json:"paused"`
	Plan   struct {
		Name string `json:"name"`
	} `json:"plan"`
	Account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
}

func (c *CloudflareClient) GetZone(ctx context.Context, zoneID string) (*CloudflareZoneInfo, error) {
	var z CloudflareZoneInfo
	if err := c.rest(ctx, "/zones/"+zoneID, nil, &z); err != nil {
		return nil, err
	}
	return &z, nil
}

// CloudflareAlertHistory is one alert Cloudflare's own notification system
// sent for the account: DDoS attacks, origin errors, certificate expiry and
// the rest of what the account's notification policies cover.
type CloudflareAlertHistory struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	AlertType     string `json:"alert_type"`
	AlertBody     string `json:"alert_body"`
	Description   string `json:"description"`
	Mechanism     string `json:"mechanism"`
	MechanismType string `json:"mechanism_type"`
	PolicyID      string `json:"policy_id"`
	Sent          string `json:"sent"`
}

func (c *CloudflareClient) AlertHistory(ctx context.Context, accountID string, since time.Time) ([]CloudflareAlertHistory, error) {
	q := url.Values{}
	q.Set("since", since.UTC().Format(time.RFC3339))
	q.Set("per_page", "200")
	var out []CloudflareAlertHistory
	if err := c.rest(ctx, "/accounts/"+accountID+"/alerting/v3/history", q, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GraphQL runs one Analytics API query. GraphQL answers 200 even when the
// query was refused, with the reason in errors[], so both are checked: a
// field the zone's plan does not include comes back that way.
func (c *CloudflareClient) GraphQL(ctx context.Context, query string, variables map[string]interface{}, out interface{}) error {
	payload, _ := json.Marshal(map[string]interface{}{"query": query, "variables": variables})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, CloudflareAPI+"/graphql", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cloudflareHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))

	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return &CloudflareError{Status: resp.StatusCode, Message: fmt.Sprintf("cloudflare graphql returned %d", resp.StatusCode)}
	}
	if len(env.Errors) > 0 {
		msgs := make([]string, 0, len(env.Errors))
		for _, e := range env.Errors {
			msgs = append(msgs, e.Message)
		}
		return &CloudflareError{Status: resp.StatusCode, Message: strings.Join(msgs, "; ")}
	}
	if resp.StatusCode >= 300 {
		return &CloudflareError{Status: resp.StatusCode, Message: fmt.Sprintf("cloudflare graphql returned %d", resp.StatusCode)}
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}
