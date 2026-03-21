package db

import (
	"log"
	"os"

	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func ConnectDB() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "kubecommit.db"
	}
	database, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})

	if err != nil {
		log.Fatal("Failed to connect to database!", err)
	}

	err = database.AutoMigrate(
		&models.User{},
		&models.UserKeys{},
		&models.Variable{},
		&models.Repository{},
		&models.YamlTemplate{},
		&models.GlobalVariable{},
		&models.BitbucketWorkspace{},
		&models.BitbucketProject{},
		&models.ArgoCDInstance{},
		&models.RefreshToken{},
	)

	if err != nil {
		log.Fatal("Failed to migrate database!", err)
	}

	DB = database
	MigrateExistingUsers()
	BootstrapAdmin()
}

func MigrateExistingUsers() {
	var adminCount int64
	DB.Model(&models.User{}).Where("role IN ('root','admin') AND deleted_at IS NULL").Count(&adminCount)
	if adminCount == 0 {
		DB.Exec("UPDATE users SET role = 'root' WHERE mfa_enabled = 1 AND role = 'user' AND deleted_at IS NULL")
	}
	DB.Exec("UPDATE users SET is_active = 1 WHERE mfa_enabled = 1 AND is_active = 0 AND deleted_at IS NULL")
}

func BootstrapAdmin() {
	var count int64
	DB.Model(&models.User{}).Count(&count)
	if count == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), 10)
		if err != nil {
			log.Fatal("Failed to hash bootstrap password:", err)
		}
		DB.Create(&models.User{
			Email:               "admin",
			PasswordHash:        string(hash),
			Role:                "bootstrap",
			ForcePasswordChange: true,
			IsActive:            true,
		})
		log.Println("Bootstrap admin user created — finish setup at first login")
	}
}
