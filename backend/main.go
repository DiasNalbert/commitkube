package main

import (
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/handlers"
	"github.com/kubecommit/backend/middleware"
)

func main() {
	db.ConnectDB()

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

	// Auth routes (public)
	app.Post("/api/auth/login", handlers.Login)
	app.Post("/api/auth/verify-mfa", handlers.VerifyMFA)
	app.Post("/api/auth/refresh", handlers.RefreshTokenHandler)
	app.Post("/api/auth/setup-init", handlers.SetupInit)
	app.Post("/api/auth/setup-confirm", handlers.SetupConfirm)

	// Protected routes
	api := app.Group("/api", middleware.AuthRequired())

	// Repositories
	api.Post("/repositories", handlers.CreateRepository)
	api.Get("/repositories", handlers.ListRepositories)
	api.Delete("/repositories/:name", handlers.DeleteRepository)
	api.Get("/repositories/:name/src", handlers.GetRepositorySrc)
	api.Get("/repositories/:name/pipelines", handlers.GetRepositoryPipelines)
	api.Get("/repositories/:name/pipelines/:pipeline_uuid/steps", handlers.GetPipelineSteps)
	api.Get("/repositories/:name/pipelines/:pipeline_uuid/steps/:step_uuid/log", handlers.GetStepLog)

	// Settings
	api.Get("/settings", handlers.GetSettings)
	api.Put("/settings", handlers.UpdateSettings)

	// YAML Templates
	api.Get("/templates", handlers.ListTemplates)
	api.Post("/templates", handlers.CreateTemplate)
	api.Put("/templates/:id", handlers.UpdateTemplate)
	api.Delete("/templates/:id", handlers.DeleteTemplate)

	// Global Variables
	api.Get("/global-vars", handlers.ListGlobalVars)
	api.Post("/global-vars", handlers.CreateGlobalVar)
	api.Put("/global-vars/:id", handlers.UpdateGlobalVar)
	api.Delete("/global-vars/:id", handlers.DeleteGlobalVar)

	// Bitbucket Workspaces
	api.Get("/workspaces", handlers.ListWorkspaces)
	api.Post("/workspaces", handlers.CreateWorkspace)
	api.Put("/workspaces/:id", handlers.UpdateWorkspace)
	api.Delete("/workspaces/:id", handlers.DeleteWorkspace)

	// Workspace Projects
	api.Get("/workspaces/:workspace_id/projects", handlers.ListProjects)
	api.Post("/workspaces/:workspace_id/projects", handlers.CreateProject)
	api.Delete("/workspaces/:workspace_id/projects/:id", handlers.DeleteProject)

	// ArgoCD Instances
	api.Get("/argocd-instances", handlers.ListArgoCDInstances)
	api.Post("/argocd-instances", handlers.CreateArgoCDInstance)
	api.Put("/argocd-instances/:id", handlers.UpdateArgoCDInstance)
	api.Delete("/argocd-instances/:id", handlers.DeleteArgoCDInstance)

	// Users
	api.Get("/users/me", handlers.GetMe)
	api.Get("/users", handlers.ListUsers)
	api.Post("/users", handlers.CreateUser)
	api.Delete("/users/:id", handlers.DeleteUser)
	api.Put("/users/:id/role", handlers.UpdateUserRole)
	api.Put("/users/:id/password", handlers.ChangePassword)

	log.Fatal(app.Listen(":8080"))
}
