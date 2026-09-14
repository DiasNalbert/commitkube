package db

import "github.com/kubecommit/backend/models"

func LogAudit(userID uint, action, resourceType, resourceName, details, ip string) {
	var user models.User
	email := ""
	if err := DB.Select("email").Where("id = ?", userID).First(&user).Error; err == nil {
		email = user.Email
	}
	DB.Create(&models.AuditLog{
		UserID:       userID,
		UserEmail:    email,
		Action:       action,
		ResourceType: resourceType,
		ResourceName: resourceName,
		Details:      details,
		IPAddress:    ip,
	})
}

func GetUserEmail(userID uint) string {
	var user models.User
	if err := DB.Select("email").Where("id = ?", userID).First(&user).Error; err == nil {
		return user.Email
	}
	return ""
}
