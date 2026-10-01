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
	// The repository's own deploy key. Empty on repositories created before
	// keys were per repository; those still clone with the workspace key.
	SSHPubKey  string `gorm:"type:text" json:"ssh_pub_key,omitempty"`
	SSHPrivKey string `gorm:"type:text" json:"-"` // encrypted
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

// Cluster is a Kubernetes cluster CommitKube talks to. Until this existed
// every call went to whatever the pod's own ServiceAccount could reach, so
// there was exactly one cluster and it was implicit.
//
// The first row is created automatically from that same ambient credential
// (in-cluster, or KUBECONFIG outside), marked Local -- so an install that has
// never configured a cluster keeps working exactly as before, and a second
// cluster is additive rather than a migration.
type Cluster struct {
	ID        uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Name      string `gorm:"uniqueIndex;not null" json:"name"`
	APIServer string `json:"api_server"`
	CACert    string `gorm:"type:text" json:"-"`
	// ServiceToken is the collector identity: the credential the background
	// pollers use. It is never used to serve a write on behalf of a user.
	ServiceToken string `gorm:"type:text" json:"-"`
	// Local means "use the ambient credential this process already has"
	// instead of APIServer/ServiceToken.
	Local       bool `gorm:"default:false" json:"local"`
	InsecureTLS bool `gorm:"default:false" json:"insecure_tls"`
	IsDefault   bool `gorm:"default:false" json:"is_default"`
	CreatedBy   uint `json:"created_by"`

	// Impersonate makes every call made for a request -- read and write alike
	// -- run as the person who asked, so the cluster decides and its audit log
	// names them. It does not and cannot cover data the pollers already
	// collected: that was gathered by the collector before any request
	// existed, and CommitKube's own namespace filter is the only fence there.
	//
	// Off by default: a cluster with no RBAC bound to the ck: identities would
	// refuse everything the moment this shipped, so turning it on is a
	// deliberate act taken once the bindings exist.
	Impersonate bool `gorm:"default:false" json:"impersonate"`
	// CanManageRBAC lets CommitKube create Roles and RoleBindings here. It is
	// the strongest privilege the product can hold -- whoever can write a
	// RoleBinding can write themselves one -- so it is opt-in per cluster,
	// and the YAML preview works without it.
	CanManageRBAC bool `gorm:"default:false" json:"can_manage_rbac"`
}

// PermissionGrant attaches one permission to a user or a group, on top of
// whatever their role already carries. Roles stay coarse; a grant is how
// someone gets one more capability without being promoted to admin to get it.
type PermissionGrant struct {
	ID          uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	SubjectType string    `gorm:"uniqueIndex:idx_pg_ident;not null" json:"subject_type"` // user | group
	SubjectID   uint      `gorm:"uniqueIndex:idx_pg_ident;not null" json:"subject_id"`
	Permission  string    `gorm:"uniqueIndex:idx_pg_ident;not null" json:"permission"`
	// Denied turns the row into a subtraction. Without it, a permission that
	// arrives with the role could never be taken away from one person without
	// demoting them, and the checkbox for it had to be disabled -- which reads
	// as a broken control rather than as a rule.
	Denied    bool `gorm:"default:false" json:"denied"`
	GrantedBy uint `json:"granted_by"`
}

// NamespaceScope narrows which namespaces of a cluster a subject may see.
//
// Absence means unrestricted, deliberately: adding the first scope row is an
// explicit act of narrowing, while defaulting to deny would lock every
// existing user out of every page the moment this shipped. The permission
// already decides whether they reach Kubernetes at all; this decides how much
// of it they see once they do.
type NamespaceScope struct {
	ID          uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	SubjectType string    `gorm:"uniqueIndex:idx_ns_ident;not null" json:"subject_type"` // user | group
	SubjectID   uint      `gorm:"uniqueIndex:idx_ns_ident;not null" json:"subject_id"`
	ClusterID   uint      `gorm:"uniqueIndex:idx_ns_ident;not null" json:"cluster_id"`
	Namespace   string    `gorm:"uniqueIndex:idx_ns_ident;not null" json:"namespace"`
	GrantedBy   uint      `json:"granted_by"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID    uint      `gorm:"index;not null;default:0" json:"cluster_id"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID   uint       `gorm:"index;not null;default:0" json:"cluster_id"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID  uint      `gorm:"index;not null;default:0" json:"cluster_id"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID  uint      `gorm:"index;not null;default:0" json:"cluster_id"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID uint      `gorm:"uniqueIndex:idx_sn_ident;index;not null;default:0" json:"cluster_id"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID uint      `gorm:"uniqueIndex:idx_se_ident;index;not null;default:0" json:"cluster_id"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID uint      `gorm:"uniqueIndex:idx_ew_ident;index;not null;default:0" json:"cluster_id"`
	BucketAt  time.Time `gorm:"uniqueIndex:idx_ew_ident;index;not null" json:"bucket_at"`

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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID uint      `gorm:"uniqueIndex:idx_df_ident;index;not null;default:0" json:"cluster_id"`
	BucketAt  time.Time `gorm:"uniqueIndex:idx_df_ident;index;not null" json:"bucket_at"`

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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID  uint       `gorm:"index;not null;default:0" json:"cluster_id"`
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
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from. Rows written
	// before CommitKube knew about more than one cluster carry 0, which the
	// migration rewrites to the default cluster.
	ClusterID uint      `gorm:"uniqueIndex:idx_leg_ident;index;not null;default:0" json:"cluster_id"`
	BucketAt  time.Time `gorm:"uniqueIndex:idx_leg_ident;index;not null" json:"bucket_at"`

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

// Deployment is one image actually starting to run on a workload. It is the
// unit the DORA metrics are computed over.
//
// It is derived from the image_change WorkloadEvent rather than from a
// pipeline result, which is the same choice the rest of the product makes:
// what the cluster runs is a fact, what a pipeline reported is a claim. Two
// consequences follow and both are intended -- a pipeline that succeeds
// without changing the running image is not a deployment, and an image
// changed by hand is one, because it happened.
//
// It is a table rather than a view over workload_events because those are
// deleted at WORKLOAD_RETENTION_DAYS, 30 by default, and the DORA bands are
// defined over months.
type Deployment struct {
	ID uint `gorm:"primarykey;autoIncrement" json:"id"`
	// ClusterID is which cluster this row was collected from.
	ClusterID uint `gorm:"uniqueIndex:idx_dep_ident;index;not null;default:0" json:"cluster_id"`

	Namespace    string    `gorm:"uniqueIndex:idx_dep_ident;index;not null" json:"namespace"`
	WorkloadKind string    `gorm:"uniqueIndex:idx_dep_ident" json:"workload_kind"`
	Workload     string    `gorm:"uniqueIndex:idx_dep_ident;index;not null" json:"workload"`
	DeployedAt   time.Time `gorm:"uniqueIndex:idx_dep_ident;index;not null" json:"deployed_at"`

	Image     string `json:"image"`
	PrevImage string `json:"prev_image"`

	// The commit that produced the image, resolved after the fact by
	// PollDelivery: reading it is a network call and must not run inside the
	// workload poller's transaction.
	//
	// LeadTimeSec stays nil when the commit could not be resolved. A
	// deployment with no commit is never given a guessed lead time -- it is
	// left out of the median and counted in the coverage figure instead.
	// Imputing a value here would be the same mistake as reporting "self"
	// for a cause nobody measured.
	RepoName    string     `gorm:"index" json:"repo_name"`
	CommitSHA   string     `json:"commit_sha"`
	CommitAt    *time.Time `json:"commit_at"`
	LeadTimeSec *int64     `json:"lead_time_sec"`
	LinkStatus  string     `gorm:"index;not null;default:'pending'" json:"link_status"` // pending | linked | unlinked
	LinkDetail  string     `json:"link_detail"`

	// Rollback marks a deployment that put back the image the workload was
	// running before the previous one. It is evidence about the deployment it
	// replaced, not about itself.
	Rollback bool `gorm:"index" json:"rollback"`

	// Outcome is pending until the failure window has elapsed: a deployment
	// ten minutes old cannot be called successful yet. The change failure
	// rate is computed over settled deployments only, or the most recent ones
	// drag it down for no reason.
	Outcome      string     `gorm:"index;not null;default:'pending'" json:"outcome"` // pending | ok | failed
	FailedReason string     `json:"failed_reason"`
	FailedAt     *time.Time `json:"failed_at"`
	RecoveredAt  *time.Time `json:"recovered_at"`
	RecoverySec  *int64     `json:"recovery_sec"`

	// DependencyIncident records that a problem did open in the window but was
	// attributed to a dependency, so it is not a change failure. Counting a
	// third party's outage against the team that deployed is the single most
	// common way this metric lies; keeping the exclusion visible is the point.
	DependencyIncident bool `json:"dependency_incident"`
}

// ---- Vault ----------------------------------------------------------------
//
// The vault is the one part of this product the server is deliberately unable
// to read. Everything else here encrypts at rest with ENCRYPTION_KEY, which
// protects a stolen database file and nothing else: the process, the env var
// and a root account all still see plaintext. That is the right trade for a
// registry credential the backend has to use, and the wrong one for a person's
// passwords. So these rows hold ciphertext the browser sealed, under a key
// Argon2id derives from a passphrase that never leaves the tab.
//
// What that costs, stated plainly: a forgotten passphrase and a lost recovery
// code mean the data is gone, nobody can search server-side, and an
// administrator cannot help anyone read anything.

// VaultKeyring is one person's identity inside the vault. Every field is
// either public or useless without the passphrase: the private key arrives
// already sealed and leaves the same way.
type VaultKeyring struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UserID    uint      `gorm:"uniqueIndex" json:"user_id"`

	// PublicKey is an ECDH P-256 key in SPKI form, base64. It is how a vault
	// key is sealed to somebody who is not online at the time.
	PublicKey string `gorm:"not null" json:"public_key"`

	// Fingerprint is SHA-256 over the public key. The server is what hands
	// public keys out, which makes the server the one party able to
	// substitute one; a fingerprint two people compare out of band is what
	// closes that gap, and the UI shows it for exactly that reason.
	Fingerprint string `gorm:"not null" json:"fingerprint"`

	// PrivateKeyEnc is the private key under AES-256-GCM, keyed by Argon2id
	// over the passphrase. Keeping it is what lets someone sign in from a
	// second machine; it is also the only offline-crackable thing here, which
	// is why the KDF is memory-hard rather than a hash iteration count.
	PrivateKeyEnc string `gorm:"not null" json:"private_key_enc"`
	KDFSalt       string `gorm:"not null" json:"kdf_salt"`
	KDFParams     string `gorm:"not null" json:"kdf_params"`

	// The same private key sealed a second time, under the recovery code.
	// Two independent wrappings of one key, so a forgotten passphrase costs a
	// piece of paper instead of every password the person owns.
	RecoveryKeyEnc string     `gorm:"not null" json:"recovery_key_enc"`
	RecoverySalt   string     `gorm:"not null" json:"recovery_salt"`
	RecoveryUsedAt *time.Time `json:"recovery_used_at"`
}

// Vault is a collection with one data key. Personal vaults have a single
// member; group vaults have the key sealed once per member, which is what
// makes sharing work without the server ever holding an unsealed copy.
type Vault struct {
	ID        uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// UUID is what the browser binds ciphertext to, so it is generated by the
	// client and never renumbered. A database primary key would be reused
	// after a restore and break every seal at once.
	UUID string `gorm:"uniqueIndex;not null" json:"uuid"`

	// The name is plaintext, and it is the one deliberate leak in the design:
	// a list of vaults has to be navigable before anything is unlocked. Names
	// are chosen by people who know that; item names are not, and they are
	// sealed.
	Name        string `gorm:"not null" json:"name"`
	Description string `json:"description"`

	Kind    string `gorm:"not null;default:'personal'" json:"kind"` // personal | group
	OwnerID uint   `gorm:"index;not null" json:"owner_id"`
	GroupID *uint  `gorm:"index" json:"group_id"`
}

// VaultMember is one sealed copy of a vault's data key. Removing the row
// removes the only copy that person could ever open, but it does not undo
// what they already read -- revoking access is not the same as forgetting,
// and the UI says so when a member is removed.
type VaultMember struct {
	ID        uint      `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	VaultID   uint      `gorm:"uniqueIndex:idx_vm_ident;not null" json:"vault_id"`
	UserID    uint      `gorm:"uniqueIndex:idx_vm_ident;not null" json:"user_id"`

	// WrappedKey is the vault key sealed to this member's public key: an
	// ephemeral ECDH public key, then a nonce, then the AES-256-GCM box.
	WrappedKey string `gorm:"not null" json:"wrapped_key"`

	Role    string `gorm:"not null;default:'reader'" json:"role"` // owner | writer | reader
	AddedBy uint   `json:"added_by"`
}

// VaultItem is split in two on purpose. The overview is what a list needs --
// a name, a username, a URL -- and is fetched with the list. The secret is
// fetched one item at a time, through an endpoint that writes an audit row,
// which is the only moment the server can honestly say somebody went looking.
// Without the split the audit log would either record nothing or record
// "opened the page", and neither is worth keeping.
type VaultItem struct {
	ID        uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	UUID    string `gorm:"uniqueIndex;not null" json:"uuid"`
	VaultID uint   `gorm:"index;not null" json:"vault_id"`

	OverviewEnc string `gorm:"type:text;not null" json:"overview_enc"`
	SecretEnc   string `gorm:"type:text;not null" json:"-"`

	// Both UUIDs and which half it is are bound into the ciphertext as
	// associated data, so a blob lifted from another item, another vault, or
	// from the overview into the secret, fails to open rather than decrypting
	// into the wrong row. Version is not bound in: it is the server that
	// reports it, so binding it would only let the server choose what the
	// client checks. It is here to refuse a stale write, which it can do.
	Version uint `gorm:"not null;default:1" json:"version"`

	CreatedBy uint `json:"created_by"`
	UpdatedBy uint `json:"updated_by"`
}
