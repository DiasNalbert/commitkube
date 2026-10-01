package models

import "time"

// PostureAssessment is one pass of the Security Posture rule catalog over a
// cluster. The rows are kept (for a year by default) because the point of the
// page is the trend: "five critical rules failing in March, two now" is the
// thing a team reports, and a single live scan cannot say it.
//
// The counts are cluster-wide, gathered with the collector identity. A caller
// whose account is scoped to some namespaces never sees these numbers as
// stored: the handler recomputes them from NamespaceResources and each rule's
// NamespaceCounts, restricted to the namespaces they may see.
type PostureAssessment struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time `gorm:"index;index:idx_pa_cluster_time,priority:2" json:"created_at"`
	ClusterID uint      `gorm:"index:idx_pa_cluster_time,priority:1;not null;default:0" json:"cluster_id"`

	// Score is passed rules / assessed rules * 100 over the Security
	// Essentials rules. Rules with nothing to assess (not_relevant) count
	// neither way; best-practice rules are reported separately.
	Score            float64 `json:"score"`
	RulesPassed      int     `json:"rules_passed"`
	RulesFailed      int     `json:"rules_failed"`
	RulesAssessed    int     `json:"rules_assessed"`
	RulesNotRelevant int     `json:"rules_not_relevant"`

	// Failed RULES per severity -- not failed resources. One rule failing on
	// forty workloads is one decision, and that is what the trend tracks.
	FailedCritical int `json:"failed_critical"`
	FailedHigh     int `json:"failed_high"`
	FailedMedium   int `json:"failed_medium"`
	FailedLow      int `json:"failed_low"`

	// Distinct resources (kind/namespace/name) failing at least one rule, and
	// distinct resources any rule looked at.
	ResourcesFailed   int `json:"resources_failed"`
	ResourcesAssessed int `json:"resources_assessed"`

	// NamespaceResources is JSON: namespace -> [failed, assessed] distinct
	// resources, "" for cluster-scoped ones. It is what lets a scoped view be
	// recomputed exactly without storing every passing resource.
	NamespaceResources string `gorm:"type:text" json:"-"`

	Trigger string `json:"trigger"` // scheduled | manual

	// CatalogVersion is the rule catalog this assessment was made with. Only
	// assessments of the current version are compared with each other.
	CatalogVersion int `gorm:"index;not null;default:0" json:"catalog_version"`
}

// PostureRuleResult is one rule's outcome within an assessment.
type PostureRuleResult struct {
	ID           uint   `gorm:"primarykey;autoIncrement" json:"id"`
	AssessmentID uint   `gorm:"index;not null" json:"assessment_id"`
	RuleID       string `gorm:"not null" json:"rule_id"`
	Severity     string `json:"severity"` // critical | high | medium | low
	Category     string `json:"category"`
	Result       string `json:"result"` // passed | failed | not_relevant
	Failed       int    `json:"failed"`
	Passed       int    `json:"passed"`

	// FailedResources is JSON: [{kind, namespace, name, detail}], capped so a
	// rule failing on every pod of a large cluster does not write megabytes per
	// pass. Failed is always the exact count.
	FailedResources string `gorm:"type:text" json:"-"`
	// NamespaceCounts is JSON: namespace -> [failed, passed], "" for
	// cluster-scoped resources.
	NamespaceCounts string `gorm:"type:text" json:"-"`
}
