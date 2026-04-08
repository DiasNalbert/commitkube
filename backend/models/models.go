package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID                  uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"-"`
	DeletedAt           gorm.DeletedAt `gorm:"index" json:"-"`
	Email               string         `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash        string         `gorm:"not null" json:"-"`
	MFASecret           string         `json:"-"`
	MFAEnabled          bool           `gorm:"default:false" json:"mfa_enabled"`
	Role                string         `gorm:"default:'user'" json:"role"`
	ForcePasswordChange bool           `gorm:"default:false" json:"-"`
	IsActive            bool           `gorm:"default:true" json:"is_active"`
	PendingEmail        string         `json:"-"`
	PendingPasswordHash string         `json:"-"`
}

type UserKeys struct {
	gorm.Model
	UserID              uint   `gorm:"uniqueIndex" json:"user_id"`
	BitbucketUsername   string `json:"bitbucket_username"`
	BitbucketAppPass    string `json:"-"`
	BitbucketSSHKey     string `json:"-"`
	BitbucketSSHPubKey  string `json:"bitbucket_ssh_pub_key"`
	BitbucketWorkspace  string `json:"bitbucket_workspace"`
	BitbucketProjectKey string `json:"bitbucket_project_key"`
	ArgoCDServerURL     string `json:"argocd_server_url"`
	ArgoCDAuthToken     string `json:"-"`
	ArgoCDSSHKey        string `json:"-"`
}

type Variable struct {
	gorm.Model
	Type     string `gorm:"not null" json:"type"`
	RepoID   *uint  `json:"repo_id"`
	KeyName  string `gorm:"not null" json:"key"`
	KeyValue string `gorm:"not null" json:"value"`
}

type Repository struct {
	ID                 uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt          time.Time      `json:"created_at"`
	UpdatedAt          time.Time      `json:"-"`
	DeletedAt          gorm.DeletedAt `gorm:"index" json:"-"`
	Name               string         `gorm:"uniqueIndex;not null" json:"name"`
	UserID             uint           `json:"user_id"`
	WorkspaceID        uint           `json:"workspace_id"`
	Status             string         `gorm:"default:'pending'" json:"status"`
	ArgoApp            string         `json:"argo_app"`
	LastCommitHash     string         `json:"-"`
	RegistryID         *uint          `json:"registry_id"`
	DockerImagePrivate bool           `gorm:"default:false" json:"docker_image_private"`
	Provider        string         `gorm:"default:'bitbucket'" json:"provider"`
	ProjectKey      string         `json:"project_key"`
	GoldenPathID    *uint          `json:"golden_path_id"`
	DeferredPayload string         `gorm:"type:text" json:"-"`
}

type YamlTemplate struct {
	ID          uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt   time.Time      `json:"-"`
	UpdatedAt   time.Time      `json:"-"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	UserID      uint           `gorm:"index" json:"user_id"`
	WorkspaceID *uint          `gorm:"index" json:"workspace_id"`
	ProjectKey  string         `json:"project_key"`
	Name        string         `gorm:"not null" json:"name"`
	Path        string         `gorm:"not null" json:"path"`
	Content     string         `gorm:"type:text" json:"content"`
	Type        string         `gorm:"not null" json:"type"`
	IsActive    bool           `gorm:"default:true" json:"is_active"`
}

type GlobalVariable struct {
	ID          uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt   time.Time      `json:"-"`
	UpdatedAt   time.Time      `json:"-"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	UserID      uint           `gorm:"index" json:"user_id"`
	WorkspaceID *uint          `gorm:"index" json:"workspace_id"`
	ProjectKey  string         `json:"project_key"`
	Key         string         `gorm:"not null" json:"key"`
	Value       string         `json:"value"`
	Secured     bool           `gorm:"default:false" json:"secured"`
}

type BitbucketWorkspace struct {
	ID          uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt   time.Time      `json:"-"`
	UpdatedAt   time.Time      `json:"-"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	UserID      uint           `gorm:"index" json:"user_id"`
	Alias       string         `gorm:"not null" json:"alias"`
	Username    string         `gorm:"not null" json:"username"`
	AppPass     string         `json:"-"`
	WorkspaceID string         `gorm:"not null" json:"workspace_id"`
	ProjectKey  string         `gorm:"not null" json:"project_key"`
	SSHPrivKey  string         `json:"-"`
	SSHPubKey   string         `json:"ssh_pub_key"`
}

type RefreshToken struct {
	gorm.Model
	UserID    uint      `gorm:"index"`
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time
	Revoked   bool `gorm:"default:false"`
}

type BitbucketProject struct {
	ID          uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt   time.Time      `json:"-"`
	UpdatedAt   time.Time      `json:"-"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	UserID      uint           `gorm:"index" json:"user_id"`
	WorkspaceID uint           `gorm:"index" json:"workspace_id"`
	ProjectKey  string         `gorm:"not null" json:"project_key"`
	Alias       string         `json:"alias"`
}

type ScanResult struct {
	ID            uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt     time.Time `json:"scanned_at"`
	RepoName      string    `gorm:"index;not null" json:"repo_name"`
	Critical      int       `json:"critical"`
	High          int       `json:"high"`
	Medium        int       `json:"medium"`
	Low           int       `json:"low"`
	Report        string    `gorm:"type:text" json:"-"`
	ScannedImage  string    `json:"scanned_image"`
	ImageCritical int       `json:"image_critical"`
	ImageHigh     int       `json:"image_high"`
	ImageMedium   int       `json:"image_medium"`
	ImageLow      int       `json:"image_low"`
	ImageReport   string    `gorm:"type:text" json:"-"`
	ImageError    string    `json:"image_error,omitempty"`
}

type RegistryCredential struct {
	ID           uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt    time.Time      `json:"-"`
	UpdatedAt    time.Time      `json:"-"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	UserID       uint           `gorm:"index" json:"user_id"`
	WorkspaceID  *uint          `gorm:"index" json:"workspace_id"`
	Alias        string         `gorm:"not null" json:"alias"`
	Host         string         `gorm:"not null" json:"host"`
	Type         string         `gorm:"not null;default:'generic'" json:"type"` // generic, ecr, gcr
	Username     string         `json:"username"`
	Password     string         `json:"-"`
	AWSAccessKey string         `json:"-"`
	AWSSecretKey string         `json:"-"`
	AWSRegion    string         `json:"aws_region"`
	GCRKeyJSON   string         `json:"-"`
}

type SMTPConfig struct {
	ID       uint   `gorm:"primarykey;autoIncrement" json:"id"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"-"`
	From     string `json:"from"`
}

type ServiceSnapshot struct {
	ID               uint      `gorm:"primarykey;autoIncrement" json:"id"`
	RecordedAt       time.Time `gorm:"index" json:"recorded_at"`
	ArgoCDInstanceID uint      `gorm:"index;column:argocd_instance_id" json:"argocd_instance_id"`
	AppName          string    `gorm:"index;not null" json:"app_name"`
	Namespace        string    `gorm:"index;not null" json:"namespace"`
	HealthStatus     string    `json:"health_status"`
	SyncStatus       string    `json:"sync_status"`
	Replicas         int       `json:"replicas"`
	ReadyReplicas    int       `json:"ready_replicas"`
	Image            string    `json:"image"`
	MaxRestartCount  int       `json:"max_restart_count"`
	RestartingPods   int       `json:"restarting_pods"`
	CPUCores         float64   `json:"cpu_cores"`
	MemoryBytes      int64     `json:"memory_bytes"`
	NetRxBytesPerSec float64   `json:"net_rx_bytes_per_sec"`
	NetTxBytesPerSec float64   `json:"net_tx_bytes_per_sec"`
}

type ServiceEvent struct {
	ID               uint      `gorm:"primarykey;autoIncrement" json:"id"`
	RecordedAt       time.Time `gorm:"index" json:"recorded_at"`
	ArgoCDInstanceID uint      `gorm:"index;column:argocd_instance_id" json:"argocd_instance_id"`
	AppName          string    `gorm:"index;not null" json:"app_name"`
	Namespace        string    `gorm:"index;not null" json:"namespace"`
	EventType        string    `json:"event_type"`
	OldValue         string    `json:"old_value"`
	NewValue         string    `json:"new_value"`
}

type ArgoCDInstance struct {
	ID               uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt        time.Time      `json:"-"`
	UpdatedAt        time.Time      `json:"-"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
	UserID           uint           `gorm:"index" json:"user_id"`
	Alias            string         `gorm:"not null" json:"alias"`
	ServerURL        string         `gorm:"not null" json:"server_url"`
	AuthToken        string         `json:"-"`
	DefaultNamespace string         `gorm:"default:'default'" json:"default_namespace"`
	DefaultProject   string         `gorm:"default:'default'" json:"default_project"`
	PrometheusURL    string         `json:"prometheus_url"`
}

// GoldenPath defines a template with guardrails for self-service repo creation.
type GoldenPath struct {
	ID                uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"-"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"-"`
	Name              string         `gorm:"uniqueIndex;not null" json:"name"`
	Description       string         `json:"description"`
	// FieldsSchema is a JSON array of FieldDef objects defining required/optional inputs.
	FieldsSchema      string         `gorm:"type:text" json:"fields_schema"`
	// ResourceLimits is a JSON map e.g. {"cpu": "500m", "memory": "256Mi"}.
	ResourceLimits    string         `gorm:"type:text" json:"resource_limits"`
	AllowedNamespaces string         `json:"allowed_namespaces"` // comma-separated
	RequiredLabels    string         `gorm:"type:text" json:"required_labels"` // JSON map
	// ApprovalWorkflow: "none" (immediate), "manual" (admin must approve).
	ApprovalWorkflow  string         `gorm:"default:'none'" json:"approval_workflow"`
	IsActive          bool           `gorm:"default:true" json:"is_active"`
}

// FieldDef describes a single input field on a GoldenPath.
type FieldDef struct {
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	Type       string   `json:"type"`               // string | number | select | bool
	Required   bool     `json:"required"`
	Options    []string `json:"options,omitempty"`  // for select type
	Validation string   `json:"validation,omitempty"` // regex pattern
	Default    string   `json:"default,omitempty"`
}

// WebhookConfig stores an outbound webhook destination.
type WebhookConfig struct {
	ID               uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"-"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
	Alias            string         `gorm:"not null" json:"alias"`
	URL              string         `gorm:"not null" json:"url"`
	// Secret is stored encrypted; used to sign payloads with HMAC-SHA256.
	Secret           string         `json:"-"`
	// Events is a JSON array of event names to subscribe to.
	Events           string         `gorm:"type:text" json:"events"`
	// PayloadTemplates is a JSON map[eventName]goTemplateString for custom payloads.
	PayloadTemplates string         `gorm:"type:text" json:"payload_templates"`
	Active           bool           `gorm:"default:true" json:"active"`
}
