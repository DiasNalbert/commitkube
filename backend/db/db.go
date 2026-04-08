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
		&models.ServiceSnapshot{},
		&models.ServiceEvent{},
		&models.RegistryCredential{},
		&models.GoldenPath{},
		&models.WebhookConfig{},
	)
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	DB.Exec("CREATE INDEX IF NOT EXISTS idx_ss_argocd_app_id ON service_snapshots (argocd_instance_id, app_name, id)")

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
