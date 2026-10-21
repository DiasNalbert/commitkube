package models

import "time"

// CloudflareZone is one zone CommitKube watches. The analytics themselves stay
// in Cloudflare and are read on demand; what is kept here is how to reach the
// zone, the thresholds its alerts fire at, and the last five-minute window
// the poller measured, so the zone list can show a pulse without a query per
// card.
type CloudflareZone struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy uint      `json:"created_by"`

	Label     string `gorm:"not null" json:"label"`
	ZoneID    string `gorm:"uniqueIndex;not null" json:"zone_id"`
	AccountID string `gorm:"not null" json:"account_id"`
	APIToken  string `gorm:"type:text;not null" json:"-"` // encrypted

	// What Cloudflare said about the zone when it was added or last polled.
	ZoneName    string `json:"zone_name"`
	AccountName string `json:"account_name"`
	Plan        string `json:"plan"`
	Status      string `json:"status"`

	Enabled bool `gorm:"not null" json:"enabled"`

	// Alert thresholds, all over a five-minute window. Zero turns a rule off.
	ThreatThreshold    int64   `gorm:"not null" json:"threat_threshold"`     // mitigated requests
	DDoSThreshold      int64   `gorm:"not null" json:"ddos_threshold"`       // requests mitigated by the L7 DDoS ruleset
	ErrorRateThreshold float64 `gorm:"not null" json:"error_rate_threshold"` // % of requests answered 5xx
	SpikeFactor        float64 `gorm:"not null" json:"spike_factor"`         // times the previous hour's average

	LastPolledAt  *time.Time `json:"last_polled_at"`
	LastError     string     `gorm:"type:text" json:"last_error"`
	LastRequests  int64      `json:"last_requests"`
	LastThreats   int64      `json:"last_threats"`
	LastErrors5xx int64      `gorm:"column:last_errors_5xx" json:"last_errors_5xx"`

	// Cloudflare's own notification history, read from the account. It needs
	// a permission the analytics do not, so its failure is kept apart: a
	// token without it still monitors the zone.
	HistorySyncedAt *time.Time `json:"history_synced_at"`
	HistoryError    string     `gorm:"type:text" json:"history_error"`
}

// CloudflareAlert is one entry in a zone's alert log. Two sources write it:
//
//   - "commitkube": a threshold rule evaluated by the poller. It opens on the
//     first window that breaches, stays one row while the breach goes on, and
//     resolves on the first window that does not.
//   - "cloudflare": an alert Cloudflare's notification system already sent,
//     copied from the account's history. Those arrive finished, so they carry
//     no open state.
type CloudflareAlert struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ZoneRefID uint      `gorm:"index;not null" json:"zone_ref_id"`

	Source     string `gorm:"index;not null" json:"source"`
	AlertType  string `gorm:"index;not null" json:"alert_type"`
	ExternalID string `json:"external_id,omitempty"`
	Severity   string `gorm:"not null" json:"severity"` // critical, high, medium, info
	Title      string `gorm:"not null" json:"title"`
	Message    string `gorm:"type:text" json:"message"`

	Value     float64 `json:"value"`
	Peak      float64 `json:"peak"`
	Threshold float64 `json:"threshold"`

	StartedAt  time.Time  `gorm:"index" json:"started_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	ResolvedAt *time.Time `json:"resolved_at"`

	// Everything else worth showing on the expanded row, as JSON.
	Details string `gorm:"type:text" json:"details"`
}
