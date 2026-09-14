package services

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"text/template"
	"time"
)

type WebhookEvent struct {
	Event   string
	Payload map[string]interface{}
}

type WebhookTarget struct {
	URL              string
	Secret           string
	Events           string
	PayloadTemplates string
}

func Dispatch(event WebhookEvent, targets []WebhookTarget) {
	for _, t := range targets {
		t := t
		go func() {
			if err := dispatch(event, t); err != nil {
				log.Printf("webhook: dispatch to %s failed: %v", t.URL, err)
			}
		}()
	}
}

func dispatch(event WebhookEvent, target WebhookTarget) error {
	if !isSubscribed(target.Events, event.Event) {
		return nil
	}

	payload, err := buildPayload(event, target.PayloadTemplates)
	if err != nil {
		return fmt.Errorf("build payload: %w", err)
	}

	req, err := http.NewRequest("POST", target.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CommitKube-Event", event.Event)
	req.Header.Set("X-CommitKube-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))

	if target.Secret != "" {
		sig := signPayload(payload, target.Secret)
		req.Header.Set("X-Hub-Signature-256", "sha256="+sig)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("receiver returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func isSubscribed(eventsJSON, event string) bool {
	if eventsJSON == "" || eventsJSON == "[]" {
		return true
	}
	var events []string
	if err := json.Unmarshal([]byte(eventsJSON), &events); err != nil {
		return true
	}
	for _, e := range events {
		if e == event || e == "*" {
			return true
		}
	}
	return false
}

func buildPayload(event WebhookEvent, templatesJSON string) ([]byte, error) {
	if templatesJSON != "" {
		var tmpls map[string]string
		if err := json.Unmarshal([]byte(templatesJSON), &tmpls); err == nil {
			if tmplStr, ok := tmpls[event.Event]; ok && tmplStr != "" {
				t, err := template.New("payload").Parse(tmplStr)
				if err == nil {
					var buf bytes.Buffer
					if err := t.Execute(&buf, event.Payload); err == nil {
						return buf.Bytes(), nil
					}
				}
			}
		}
	}

	out := map[string]interface{}{
		"event":     event.Event,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	for k, v := range event.Payload {
		out[k] = v
	}
	return json.Marshal(out)
}

func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func DefaultPayload(event string, fields map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{"event": event}
	for k, v := range fields {
		out[k] = v
	}
	return out
}

const SlackPayloadTemplate = `{"text": "[CommitKube] {{.event}}: {{range $k,$v := .}}{{$k}}={{$v}} {{end}}"}`

func IsSlackURL(url string) bool {
	return strings.Contains(url, "hooks.slack.com") || strings.Contains(url, "hooks.slack-edge.com")
}
