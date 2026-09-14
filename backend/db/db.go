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

	// scan_results.updated_at is new. Rows written before it existed come back
	// as the zero time, which would read as "never scanned" and send every
	// repository through a full rescan on the first pass -- and would show the
	// year 1 as the scan date until one ran. They were last written when they
	// were created, so say that.
	DB.Exec("UPDATE scan_results SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = '' OR updated_at < '0001-01-02'")

	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ps_ns_pod_time ON pod_snapshots (namespace, pod_name, recorded_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ps_workload_time ON pod_snapshots (workload, recorded_at)")
	DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_pp_open ON pod_problems (namespace, pod_name, kind) WHERE closed_at IS NULL")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ws_key_time ON workload_snapshots (namespace, kind, name, recorded_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_we_key_time ON workload_events (namespace, name, recorded_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_se_src ON service_edges (src_namespace, src_kind, src_name)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_se_dst ON service_edges (dst_namespace, dst_kind, dst_name)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ew_workload_time ON error_windows (namespace, workload, bucket_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_df_src_time ON dependency_failures (src_namespace, src_name, bucket_at)")
	DB.Exec("CREATE INDEX IF NOT EXISTS idx_leg_workload_time ON log_error_groups (namespace, workload, bucket_at)")
	DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_sp_open ON service_problems (namespace, workload, kind) WHERE closed_at IS NULL")

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
