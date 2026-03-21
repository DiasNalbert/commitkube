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
	ID          uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"-"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	Name        string         `gorm:"uniqueIndex;not null" json:"name"`
	UserID      uint           `json:"user_id"`
	WorkspaceID uint           `json:"workspace_id"`
	Status      string         `gorm:"default:'pending'" json:"status"`
	ArgoApp     string         `json:"argo_app"`
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

type ArgoCDInstance struct {
	ID        uint           `gorm:"primarykey;autoIncrement" json:"id"`
	CreatedAt time.Time      `json:"-"`
	UpdatedAt time.Time      `json:"-"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	UserID    uint           `gorm:"index" json:"user_id"`
	Alias     string         `gorm:"not null" json:"alias"`
	ServerURL string         `gorm:"not null" json:"server_url"`
	AuthToken string         `json:"-"`
}
