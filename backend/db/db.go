package db

import (
	"log"
	"os"

	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

// BackfillCollectedCluster adopts pre-multicluster rows into the default
// cluster: they were all gathered from the one cluster this process could
// reach, and left at 0 they would match no cluster filter and vanish from
// every page.
//
// It must run AFTER the default cluster row exists, so main calls it once
// EnsureDefaultCluster has returned -- not from ConnectDB, which happens
// first. After the first pass no row has 0 left.
func BackfillCollectedCluster() {
	var defaultID uint
	row := DB.Model(&models.Cluster{}).Where("is_default = ?", true).Select("id")
	if err := row.Scan(&defaultID).Error; err != nil || defaultID == 0 {
		return // no default cluster yet; the next start will do it
	}
	for _, table := range []string{
		"pod_snapshots", "pod_problems", "workload_snapshots", "workload_events",
		"service_nodes", "service_edges", "error_windows", "dependency_failures",
		"service_problems", "log_error_groups",
	} {
		DB.Exec("UPDATE "+table+" SET cluster_id = ? WHERE cluster_id = 0 OR cluster_id IS NULL", defaultID)
	}
}

func ConnectDB() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "kubecommit.db"
	}

	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	// These unique indexes gained cluster_id. AutoMigrate creates a missing
	// index but never alters one that already exists under the same name, so
	// an upgraded database would keep enforcing the cluster-blind version --
	// and two clusters sharing a namespace and a name would collide, one
	// silently overwriting the other. Dropping them first lets AutoMigrate
	// rebuild them with the cluster included. Widening a unique index never
	// invalidates existing rows, so this is safe to repeat.
	for _, idx := range []string{
		"idx_sn_ident", "idx_se_ident", "idx_ew_ident", "idx_df_ident", "idx_leg_ident",
	} {
		DB.Exec("DROP INDEX IF EXISTS " + idx)
	}

	err = DB.AutoMigrate(
		&models.User{},
		&models.UserKeys{},
		&models.Repository{},
		&models.YamlTemplate{},
		&models.GlobalVariable{},
		&models.BitbucketWorkspace{},
		&models.RefreshToken{},
		&models.BitbucketProject{},
		&models.ArgoCDInstance{},
		&models.Cluster{},
		&models.PermissionGrant{},
		&models.SMTPConfig{},
		&models.ScanResult{},
		&models.ScanHistory{},
		&models.RegistryCredential{},
		&models.GoldenPath{},
		&models.WebhookConfig{},
		&models.UserGroup{},
		&models.UserGroupMember{},
		&models.UserGroupWorkspace{},
		&models.AuditLog{},
		&models.NotificationConfig{},
		&models.PodSnapshot{},
		&models.PodProblem{},
		&models.WorkloadSnapshot{},
		&models.WorkloadEvent{},
		&models.ServiceNode{},
		&models.ServiceEdge{},
		&models.ErrorWindow{},
		&models.DependencyFailure{},
		&models.ServiceProblem{},
		&models.LogErrorGroup{},
	)
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	// Reads are always scoped to one cluster now, so cluster_id leads every
	// index that used to start with the namespace.
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ps_cluster_ns_pod_time ON pod_snapshots (cluster_id, namespace, pod_name, recorded_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ws_cluster_key_time ON workload_snapshots (cluster_id, namespace, kind, name, recorded_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ew_cluster_workload_time ON error_windows (cluster_id, namespace, workload, bucket_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_se_cluster_src ON service_edges (cluster_id, src_namespace, src_kind, src_name)")

	// scan_results.updated_at is new. Rows written before it existed come back
	// as the zero time, which would read as "never scanned" and send every
	// repository through a full rescan on the first pass -- and would show the
	// year 1 as the scan date until one ran. They were last written when they
	// were created, so say that.
	DB.Exec("UPDATE scan_results SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = '' OR updated_at < '0001-01-02'")

	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ps_ns_pod_time ON pod_snapshots (namespace, pod_name, recorded_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ps_workload_time ON pod_snapshots (workload, recorded_at)")
	// The "one open problem per thing" indexes have to include the cluster, or
	// the same workload name in two clusters would collapse into one row.
	// IF NOT EXISTS would keep the old, cluster-blind index on an existing
	// database, so the old name is dropped explicitly first.
	DB.Exec("DROP INDEX IF EXISTS idx_pp_open")
	DB.Exec("DROP INDEX IF EXISTS idx_sp_open")
	DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_pp_open_cluster ON pod_problems (cluster_id, namespace, pod_name, kind) WHERE closed_at IS NULL")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ws_key_time ON workload_snapshots (namespace, kind, name, recorded_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_we_key_time ON workload_events (namespace, name, recorded_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_se_src ON service_edges (src_namespace, src_kind, src_name)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_se_dst ON service_edges (dst_namespace, dst_kind, dst_name)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ew_workload_time ON error_windows (namespace, workload, bucket_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_df_src_time ON dependency_failures (src_namespace, src_name, bucket_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_leg_workload_time ON log_error_groups (namespace, workload, bucket_at)")
	DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_sp_open_cluster ON service_problems (cluster_id, namespace, workload, kind) WHERE closed_at IS NULL")

	bootstrapAdmin()
}

func bootstrapAdmin() {
	var count int64
	DB.Model(&models.User{}).Count(&count)
	if count > 0 {
		return
	}

	password := os.Getenv("ADMIN_PASSWORD")
	if password == "" {
		password = "admin123"
	}
	email := os.Getenv("ADMIN_EMAIL")
	if email == "" {
		email = "admin@commitkube.local"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Warning: failed to hash admin password: %v", err)
		return
	}

	admin := models.User{
		Email:        email,
		PasswordHash: string(hash),
		Role:         "root",
		IsActive:     true,
	}
	if err := DB.Create(&admin).Error; err != nil {
		log.Printf("Warning: failed to create admin user: %v", err)
	} else {
		log.Printf("Bootstrap: admin user created (%s)", email)
	}
}
