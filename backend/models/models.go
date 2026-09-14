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
	Provider           string         `gorm:"default:'bitbucket'" json:"provider"`
	ProjectKey         string         `json:"project_key"`
	GoldenPathID       *uint          `json:"golden_path_id"`
	DeferredPayload    string         `gorm:"type:text" json:"-"`
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
	UserID    uint   `gorm:"index"`
	Token     string `gorm:"uniqueIndex;not null"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// There is one row per repository, rewritten in place by every scan, so
	// CreatedAt is when the repository was first ever scanned and UpdatedAt is
	// when it was last looked at. Staleness -- and the date the dashboards
	// show -- has to come from UpdatedAt: CreatedAt never moves again.
	CreatedAt    time.Time `json:"first_scanned_at"`
	UpdatedAt    time.Time `json:"scanned_at"`
	RepoName     string    `gorm:"index;not null" json:"repo_name"`
	Critical     int       `json:"critical"`
	High         int       `json:"high"`
	Medium       int       `json:"medium"`
	Low          int       `json:"low"`
	Report       string    `gorm:"type:text" json:"-"`
	ScannedImage string    `json:"scanned_image"`
	ImageSource  string    `json:"image_source"` // deployed | base

	ImageCritical int    `json:"image_critical"`
	ImageHigh     int    `json:"image_high"`
	ImageMedium   int    `json:"image_medium"`
	ImageLow      int    `json:"image_low"`
	ImageReport   string `gorm:"type:text" json:"-"`
	ImageError    string `json:"image_error,omitempty"`
}

type ScanHistory struct {
	ID            uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt     time.Time `gorm:"index" json:"scanned_at"`
	RepoName      string    `gorm:"index;not null" json:"repo_name"`
	Critical      int       `json:"critical"`
	High          int       `json:"high"`
	Medium        int       `json:"medium"`
	Low           int       `json:"low"`
	ImageCritical int       `json:"image_critical"`
	ImageHigh     int       `json:"image_high"`
	ImageMedium   int       `json:"image_medium"`
	ImageLow      int       `json:"image_low"`
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
}

type GoldenPath struct {
	ID                uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"-"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"-"`
	Name              string         `gorm:"uniqueIndex;not null" json:"name"`
	Description       string         `json:"description"`
	FieldsSchema      string         `gorm:"type:text" json:"fields_schema"`
	ResourceLimits    string         `gorm:"type:text" json:"resource_limits"`
	AllowedNamespaces string         `json:"allowed_namespaces"`
	RequiredLabels    string         `gorm:"type:text" json:"required_labels"`
	ApprovalWorkflow  string         `gorm:"default:'none'" json:"approval_workflow"`
	IsActive          bool           `gorm:"default:true" json:"is_active"`
}

type FieldDef struct {
	Key        string   `json:"key"`
	Label      string   `json:"label"`
	Type       string   `json:"type"`
	Required   bool     `json:"required"`
	Options    []string `json:"options,omitempty"`
	Validation string   `json:"validation,omitempty"`
	Default    string   `json:"default,omitempty"`
}

type WebhookConfig struct {
	ID               uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"-"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
	Alias            string         `gorm:"not null" json:"alias"`
	URL              string         `gorm:"not null" json:"url"`
	Secret           string         `json:"-"`
	Events           string         `gorm:"type:text" json:"events"`
	PayloadTemplates string         `gorm:"type:text" json:"payload_templates"`
	Active           bool           `gorm:"default:true" json:"active"`
}

type UserGroup struct {
	ID          uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	Name        string         `gorm:"uniqueIndex;not null" json:"name"`
	Description string         `json:"description"`
}

type UserGroupMember struct {
	ID      uint `gorm:"primarykey;autoIncrement" json:"id"`
	GroupID uint `gorm:"index;not null" json:"group_id"`
	UserID  uint `gorm:"index;not null" json:"user_id"`
}

type UserGroupWorkspace struct {
	ID          uint `gorm:"primarykey;autoIncrement" json:"id"`
	GroupID     uint `gorm:"index;not null" json:"group_id"`
	WorkspaceID uint `gorm:"index;not null" json:"workspace_id"`
}

type AuditLog struct {
	ID           uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt    time.Time `gorm:"index" json:"created_at"`
	UserID       uint      `gorm:"index" json:"user_id"`
	UserEmail    string    `json:"user_email"`
	Action       string    `gorm:"index;not null" json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceName string    `json:"resource_name"`
	Details      string    `gorm:"type:text" json:"details"`
	IPAddress    string    `json:"ip_address"`
}

type NotificationConfig struct {
	ID        uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	Name      string         `gorm:"not null" json:"name"`
	Type      string         `gorm:"not null" json:"type"`    // "teams", "webhook", "email"
	URL       string         `gorm:"type:text" json:"url"`    // webhook/teams URL
	Email     string         `json:"email"`                   // for email type
	Events    string         `gorm:"type:text" json:"events"` // JSON array: ["scan.critical","pipeline.failed","repo.created"]
	Active    bool           `gorm:"default:true" json:"active"`
}

// PodSnapshot is a point-in-time sample of a pod's real resource usage,
// collected from metrics.k8s.io (metrics-server) and cross-referenced with
// the pod spec's requests/limits. metrics-server keeps no history of its own,
// so the time series only exists because we sample and store it here.
type PodSnapshot struct {
	ID           uint      `gorm:"primarykey;autoIncrement" json:"id"`
	RecordedAt   time.Time `gorm:"index" json:"recorded_at"`
	Namespace    string    `gorm:"index;not null" json:"namespace"`
	PodName      string    `gorm:"index;not null" json:"pod_name"`
	Workload     string    `gorm:"index" json:"workload"`
	WorkloadKind string    `json:"workload_kind"`
	NodeName     string    `gorm:"index" json:"node_name"`
	Phase        string    `json:"phase"`
	Ready        bool      `json:"ready"`
	RestartCount int       `json:"restart_count"`
	Image        string    `json:"image"`
	CPUCores     float64   `json:"cpu_cores"`
	CPURequests  float64   `json:"cpu_requests"`
	CPULimits    float64   `json:"cpu_limits"`
	CPUPct       float64   `json:"cpu_pct"`
	MemBytes     int64     `json:"mem_bytes"`
	MemRequests  int64     `json:"mem_requests"`
	MemLimits    int64     `json:"mem_limits"`
	MemPct       float64   `json:"mem_pct"`
	ThrottledPct float64   `json:"throttled_pct"`
}

// PodProblem is an open/closed condition detected on a pod. Unlike a raw
// threshold alert it has a lifecycle: it opens once, accumulates occurrences
// while it persists, and closes when the condition clears.
type PodProblem struct {
	ID          uint       `gorm:"primarykey;autoIncrement" json:"id"`
	OpenedAt    time.Time  `gorm:"index" json:"opened_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	ClosedAt    *time.Time `gorm:"index" json:"closed_at"`
	Namespace   string     `gorm:"index" json:"namespace"`
	PodName     string     `gorm:"index" json:"pod_name"`
	Workload    string     `gorm:"index" json:"workload"`
	NodeName    string     `json:"node_name"`
	Kind        string     `gorm:"index;not null" json:"kind"`
	Severity    string     `gorm:"index" json:"severity"`
	Title       string     `json:"title"`
	Detail      string     `gorm:"type:text" json:"detail"`
	Value       float64    `json:"value"`
	Occurrences int        `json:"occurrences"`
}

// WorkloadSnapshot is a periodic sample of one workload's replica state, read
// from the Kubernetes apps API. It serves the same purpose as the ArgoCD-based
// monitoring it replaced -- uptime and change history -- but is keyed on the
// real cluster object rather than on an ArgoCD Application name.
type WorkloadSnapshot struct {
	ID         uint      `gorm:"primarykey;autoIncrement" json:"id"`
	RecordedAt time.Time `gorm:"index" json:"recorded_at"`
	Namespace  string    `gorm:"index;not null" json:"namespace"`
	Kind       string    `gorm:"index;not null" json:"kind"`
	Name       string    `gorm:"index;not null" json:"name"`
	Desired    int32     `json:"desired"`
	Ready      int32     `json:"ready"`
	Updated    int32     `json:"updated"`
	Available  int32     `json:"available"`
	Image      string    `json:"image"`
	Status     string    `json:"status"` // healthy | progressing | degraded | scaled_zero
}

// WorkloadEvent records a transition worth showing in a change history:
// a status flip, a rescale, or a new image rolling out.
type WorkloadEvent struct {
	ID         uint      `gorm:"primarykey;autoIncrement" json:"id"`
	RecordedAt time.Time `gorm:"index" json:"recorded_at"`
	Namespace  string    `gorm:"index;not null" json:"namespace"`
	Kind       string    `json:"kind"`
	Name       string    `gorm:"index;not null" json:"name"`
	EventType  string    `json:"event_type"` // status_change | replicas_change | image_change
	OldValue   string    `json:"old_value"`
	NewValue   string    `json:"new_value"`
}

// ServiceNode is one participant in the service map: a workload, an Ingress
// that lets traffic in, or a target outside the cluster. Nodes are discovered,
// never registered by hand -- nothing here is typed in by a user.
//
// FirstSeen/LastSeen give the node a lifetime, so a workload that is deleted
// fades out of the map on retention instead of lingering forever.
type ServiceNode struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `gorm:"index" json:"last_seen"`
	Namespace string    `gorm:"uniqueIndex:idx_sn_ident;not null" json:"namespace"`
	Kind      string    `gorm:"uniqueIndex:idx_sn_ident;not null" json:"kind"` // Deployment | StatefulSet | DaemonSet | Service | Ingress | External
	Name      string    `gorm:"uniqueIndex:idx_sn_ident;not null" json:"name"`
	Services  string    `json:"services"` // Service names fronting this workload, comma separated
	Hosts     string    `json:"hosts"`    // Ingress hostnames, or the address of an external target
	Replicas  int32     `json:"replicas"`
	Status    string    `json:"status"`   // healthy | progressing | degraded | scaled_zero | unknown
	External  bool      `json:"external"` // outside the cluster: a managed database, a third-party API
}

// ServiceEdge is one directed dependency between two ServiceNodes, inferred
// from what the cluster declares -- an env var pointing at a Service, an
// Ingress backend, a NetworkPolicy peer. It is therefore intent, not measured
// traffic: the edge says "this is wired up to call that", not "this called
// that N times".
//
// Observed is the seam for the eBPF layer that comes later. Until it lands
// every row is false, and the frontend labels the whole map as declared.
type ServiceEdge struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	UpdatedAt time.Time `json:"updated_at"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `gorm:"index" json:"last_seen"`

	SrcNamespace string `gorm:"uniqueIndex:idx_se_ident;index" json:"src_namespace"`
	SrcKind      string `gorm:"uniqueIndex:idx_se_ident" json:"src_kind"`
	SrcName      string `gorm:"uniqueIndex:idx_se_ident" json:"src_name"`
	DstNamespace string `gorm:"uniqueIndex:idx_se_ident;index" json:"dst_namespace"`
	DstKind      string `gorm:"uniqueIndex:idx_se_ident" json:"dst_kind"`
	DstName      string `gorm:"uniqueIndex:idx_se_ident" json:"dst_name"`
	Port         string `gorm:"uniqueIndex:idx_se_ident" json:"port"`
	Source       string `gorm:"uniqueIndex:idx_se_ident;index" json:"source"` // env | configmap | mount | ingress | networkpolicy | istio | externalname

	Protocol   string `json:"protocol"`   // http | https | grpc | postgres | redis | amqp | tcp | ...
	Evidence   string `json:"evidence"`   // the exact declaration the edge was read from
	Confidence string `json:"confidence"` // high | medium | low
	Observed   bool   `json:"observed"`   // set by the traffic layer, not by discovery
}

// ErrorWindow is one time bucket of inbound request outcomes for a workload.
// It answers "is this application returning errors" without any judgement about
// whose fault that is -- attribution happens in ServiceProblem, against the
// DependencyFailure rows for the same bucket.
//
// Source records how the bucket was measured, because the two collectors see
// different traffic and must not be summed: "ingress" is north-south traffic
// read from the ingress controller's access log, "logs" is error-level lines
// counted in the container's own output, and "ebpf" is the L7 layer.
type ErrorWindow struct {
	ID       uint      `gorm:"primarykey;autoIncrement" json:"id"`
	BucketAt time.Time `gorm:"uniqueIndex:idx_ew_ident;index;not null" json:"bucket_at"`

	Namespace    string `gorm:"uniqueIndex:idx_ew_ident;index;not null" json:"namespace"`
	WorkloadKind string `gorm:"uniqueIndex:idx_ew_ident" json:"workload_kind"`
	Workload     string `gorm:"uniqueIndex:idx_ew_ident;index;not null" json:"workload"`
	Source       string `gorm:"uniqueIndex:idx_ew_ident;index;not null" json:"source"` // ingress | logs | ebpf

	Requests  int64 `json:"requests"`
	Status4xx int64 `json:"status_4xx"`
	Status5xx int64 `json:"status_5xx"`
	ErrorLogs int64 `json:"error_logs"` // error-level lines, only meaningful for source=logs

	TopStatus string `json:"top_status"` // "502 x31, 500 x4", most frequent first
	TopPath   string `json:"top_path"`   // the request path erroring most in this bucket
	Sample    string `gorm:"type:text" json:"sample"`
}

// DependencyFailure counts the L4 and DNS failures one workload hit while
// calling a dependency, in the same buckets as ErrorWindow. This is the row
// that turns "my app returns 500" into "my app returns 500 because X is down":
// a third party being unreachable shows up here in the clear, so none of these
// counters need the request body decrypted.
//
// Dst identifies a node in the service map, so an External target resolves to
// the same row the topology already created for it.
type DependencyFailure struct {
	ID       uint      `gorm:"primarykey;autoIncrement" json:"id"`
	BucketAt time.Time `gorm:"uniqueIndex:idx_df_ident;index;not null" json:"bucket_at"`

	SrcNamespace string `gorm:"uniqueIndex:idx_df_ident;index;not null" json:"src_namespace"`
	SrcKind      string `gorm:"uniqueIndex:idx_df_ident" json:"src_kind"`
	SrcName      string `gorm:"uniqueIndex:idx_df_ident;not null" json:"src_name"`
	DstNamespace string `gorm:"uniqueIndex:idx_df_ident" json:"dst_namespace"`
	DstKind      string `gorm:"uniqueIndex:idx_df_ident" json:"dst_kind"`
	DstName      string `gorm:"uniqueIndex:idx_df_ident;index" json:"dst_name"`
	Port         string `gorm:"uniqueIndex:idx_df_ident" json:"port"`
	Source       string `gorm:"uniqueIndex:idx_df_ident" json:"source"` // ebpf

	DstHost string `json:"dst_host"` // hostname actually dialled, for External targets

	Attempts    int64 `json:"attempts"`
	ConnRefused int64 `json:"conn_refused"`
	ConnTimeout int64 `json:"conn_timeout"`
	ConnReset   int64 `json:"conn_reset"`
	DNSFailed   int64 `json:"dns_failed"`
	TLSFailed   int64 `json:"tls_failed"`
}

// Failures is every way a call to the dependency did not complete.
func (d DependencyFailure) Failures() int64 {
	return d.ConnRefused + d.ConnTimeout + d.ConnReset + d.DNSFailed + d.TLSFailed
}

// ServiceProblem is an application-level incident: the workload is serving
// errors even though its pods are Ready and the cluster is healthy, which is
// precisely the case PodProblem cannot see. It follows the same open/accumulate
// /close lifecycle as PodProblem.
//
// The Cause fields are the point of the model. CauseKind "dependency" means the
// errors line up with a dependency that was failing at L4 in the same window,
// and the blame belongs to CauseName -- often an External node, a third party.
// "self" means the workload was erroring with every dependency answering
// normally. "unknown" means nothing was observed either way.
//
// CauseSource records where the verdict came from, and the two are not equally
// strong. "ebpf" is measured: the traffic layer watched the calls. "logs" is
// inferred: the application said in its own output that it could not reach
// something. Inference is weaker evidence -- the message may be stale, retried
// or swallowed -- but for a batch job or an RPA it is usually the only evidence
// there is, and it is far better than reporting "unknown".
type ServiceProblem struct {
	ID         uint       `gorm:"primarykey;autoIncrement" json:"id"`
	OpenedAt   time.Time  `gorm:"index" json:"opened_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	ClosedAt   *time.Time `gorm:"index" json:"closed_at"`

	Namespace    string `gorm:"index" json:"namespace"`
	WorkloadKind string `json:"workload_kind"`
	Workload     string `gorm:"index" json:"workload"`
	Kind         string `gorm:"index;not null" json:"kind"` // http_5xx | error_logs | dependency_failure
	Severity     string `gorm:"index" json:"severity"`      // critical | warning | info

	Title  string  `json:"title"`
	Detail string  `gorm:"type:text" json:"detail"`
	Value  float64 `json:"value"` // error rate percent, or failures per minute

	Requests int64 `json:"requests"`
	Errors   int64 `json:"errors"`

	CauseKind      string `gorm:"index" json:"cause_kind"`   // dependency | self | unknown
	CauseSource    string `gorm:"index" json:"cause_source"` // ebpf | logs | none
	CauseNamespace string `json:"cause_namespace"`
	CauseNodeKind  string `json:"cause_node_kind"`
	CauseName      string `json:"cause_name"`
	CauseHost      string `json:"cause_host"`
	CauseDetail    string `gorm:"type:text" json:"cause_detail"`

	Occurrences int `json:"occurrences"`
}

// LogErrorGroup is one class of error found in application logs, counted per
// five-minute bucket exactly like ErrorWindow so the same overwrite-on-rewrite
// idempotency holds. Aggregation across buckets happens on read.
//
// Fingerprint is a hash of Template, the message with its variable parts
// replaced by placeholders, so that a thousand lines differing only in an order
// id collapse into one group with a count of a thousand. Without that, a log
// catalogue is just the log again.
//
// Class is what makes the catalogue answer the question that matters to a
// batch job or an RPA: whether the run failed because the site it drives was
// unreachable, or because the automation itself broke. It is read from the
// error text, which for this kind of failure is unusually explicit -- a browser
// automation reports net::ERR_NAME_NOT_RESOLVED, an HTTP client reports
// ECONNREFUSED. Target carries the host the message named, when it named one.
type LogErrorGroup struct {
	ID       uint      `gorm:"primarykey;autoIncrement" json:"id"`
	BucketAt time.Time `gorm:"uniqueIndex:idx_leg_ident;index;not null" json:"bucket_at"`

	Namespace    string `gorm:"uniqueIndex:idx_leg_ident;index;not null" json:"namespace"`
	WorkloadKind string `gorm:"uniqueIndex:idx_leg_ident" json:"workload_kind"`
	Workload     string `gorm:"uniqueIndex:idx_leg_ident;index;not null" json:"workload"`
	Fingerprint  string `gorm:"uniqueIndex:idx_leg_ident;index;not null" json:"fingerprint"`

	Template string `gorm:"type:text" json:"template"`
	Class    string `gorm:"index" json:"class"` // dependency_unreachable | dependency_timeout | dependency_http | app_exception | unknown
	Target   string `gorm:"index" json:"target"`

	Count   int64  `json:"count"`
	Sample  string `gorm:"type:text" json:"sample"`
	LastPod string `json:"last_pod"`
}
