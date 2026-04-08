package main

import (
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/handlers"
	"github.com/kubecommit/backend/middleware"
)

func main() {
	db.ConnectDB()
	_ = crypto.MasterKey() // validate ENCRYPTION_KEY at startup

	go func() {
		interval := 5 * time.Minute
		if v := os.Getenv("MONITORING_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
			}
		}
		handlers.PollMonitoring()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			handlers.PollMonitoring()
		}
	}()

	app := fiber.New(fiber.Config{
		BodyLimit: 50 * 1024 * 1024,
	})

	app.Use(logger.New())
	allowOrigins := os.Getenv("CORS_ORIGIN")
	if allowOrigins == "" {
		allowOrigins = "*"
	}
	app.Use(cors.New(cors.Config{
		AllowOrigins:     allowOrigins,
		AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
		AllowMethods:     "GET, POST, PUT, DELETE, PATCH, OPTIONS",
		AllowCredentials: allowOrigins != "*",
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "Welcome to CommitKube API"})
	})

	app.Post("/api/auth/login", handlers.Login)
	app.Post("/api/auth/verify-mfa", handlers.VerifyMFA)
	app.Post("/api/auth/refresh", handlers.RefreshTokenHandler)
	app.Post("/api/auth/setup-init", handlers.SetupInit)
	app.Post("/api/auth/setup-confirm", handlers.SetupConfirm)

	api := app.Group("/api", middleware.AuthRequired())

	api.Post("/repositories", handlers.CreateRepository)
	api.Post("/repositories/import", handlers.ImportRepository)
	api.Post("/repositories/import-project", handlers.ImportProject)
	api.Get("/repositories", handlers.ListRepositories)
	api.Delete("/repositories/:name", handlers.DeleteRepository)
	api.Get("/repositories/:name/src", handlers.GetRepositorySrc)
	api.Put("/repositories/:name/src", handlers.CommitFileEdit)
	api.Get("/repositories/:name/branches", handlers.GetRepositoryBranches)
	api.Get("/repositories/:name/commits", handlers.GetRepositoryCommits)
	api.Get("/repositories/:name/pipelines", handlers.GetRepositoryPipelines)
	api.Get("/repositories/:name/pipelines/:pipeline_uuid/steps", handlers.GetPipelineSteps)
	api.Get("/repositories/:name/pipelines/:pipeline_uuid/steps/:step_uuid/log", handlers.GetStepLog)
	api.Post("/repositories/:name/scan", handlers.RunTrivyScan)
	api.Get("/scan-dashboard", handlers.GetScanDashboard)
	api.Get("/scan-dashboard/:name", handlers.GetRepoScanDetail)

	api.Get("/settings", handlers.GetSettings)
	api.Put("/settings", handlers.UpdateSettings)

	api.Get("/smtp", handlers.GetSMTPConfig)
	api.Put("/smtp", handlers.UpdateSMTPConfig)

	api.Get("/templates", handlers.ListTemplates)
	api.Post("/templates", handlers.CreateTemplate)
	api.Put("/templates/:id", handlers.UpdateTemplate)
	api.Delete("/templates/:id", handlers.DeleteTemplate)

	api.Get("/global-vars", handlers.ListGlobalVars)
	api.Post("/global-vars", handlers.CreateGlobalVar)
	api.Put("/global-vars/:id", handlers.UpdateGlobalVar)
	api.Delete("/global-vars/:id", handlers.DeleteGlobalVar)

	api.Get("/workspaces", handlers.ListWorkspaces)
	api.Post("/workspaces", handlers.CreateWorkspace)
	api.Put("/workspaces/:id", handlers.UpdateWorkspace)
	api.Delete("/workspaces/:id", handlers.DeleteWorkspace)

	api.Get("/workspaces/:workspace_id/projects", handlers.ListProjects)
	api.Post("/workspaces/:workspace_id/projects", handlers.CreateProject)
	api.Delete("/workspaces/:workspace_id/projects/:id", handlers.DeleteProject)

	api.Get("/argocd-instances", handlers.ListArgoCDInstances)
	api.Post("/argocd-instances", handlers.CreateArgoCDInstance)
	api.Put("/argocd-instances/:id", handlers.UpdateArgoCDInstance)
	api.Delete("/argocd-instances/:id", handlers.DeleteArgoCDInstance)

	api.Get("/registry-credentials", handlers.ListRegistryCredentials)
	api.Post("/registry-credentials", handlers.CreateRegistryCredential)
	api.Put("/registry-credentials/:id", handlers.UpdateRegistryCredential)
	api.Delete("/registry-credentials/:id", handlers.DeleteRegistryCredential)

	api.Get("/dashboard/summary", handlers.GetDashboardSummary)

	api.Get("/monitoring/dashboard", handlers.GetMonitoringDashboard)
	api.Get("/monitoring/logs", handlers.GetApplicationLogs)
	api.Get("/monitoring/logs/stream", handlers.StreamApplicationLogs)
	api.Post("/monitoring/restart", handlers.RestartApplication)
	api.Get("/monitoring/history", handlers.GetAppHistory)
	api.Delete("/monitoring/history", handlers.ClearMonitoringHistory)
	api.Get("/monitoring/export", handlers.ExportMonitoringHistory)
	api.Get("/monitoring/metrics", handlers.GetAppMetrics)

	api.Get("/users/me", handlers.GetMe)
	api.Get("/users/me/keys", handlers.GetMyKeys)
	api.Put("/users/me/keys", handlers.SaveMyKeys)
	api.Get("/users", handlers.ListUsers)
	api.Post("/users", handlers.CreateUser)
	api.Delete("/users/:id", handlers.DeleteUser)
	api.Put("/users/:id/role", handlers.UpdateUserRole)
	api.Put("/users/:id/password", handlers.ChangePassword)
	api.Delete("/users/:id/mfa", handlers.ResetUserMFA)

	// Webhooks
	api.Get("/webhooks", handlers.ListWebhookConfigs)
	api.Post("/webhooks", handlers.CreateWebhookConfig)
	api.Put("/webhooks/:id", handlers.UpdateWebhookConfig)
	api.Delete("/webhooks/:id", handlers.DeleteWebhookConfig)
	api.Post("/webhooks/:id/test", handlers.TestWebhookConfig)
	api.Get("/webhooks/events", func(c *fiber.Ctx) error {
		return c.SendString(handlers.WebhookEventsJSON())
	})

	// Golden Paths
	api.Get("/golden-paths", handlers.ListGoldenPaths)
	api.Post("/golden-paths", handlers.CreateGoldenPath)
	api.Get("/golden-paths/:id", handlers.GetGoldenPath)
	api.Put("/golden-paths/:id", handlers.UpdateGoldenPath)
	api.Delete("/golden-paths/:id", handlers.DeleteGoldenPath)
	api.Post("/repositories/:name/approve", handlers.ApproveRepository)

	log.Fatal(app.Listen(":8080"))
}
