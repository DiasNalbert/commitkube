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

	// A cluster row has to exist before any poller or handler resolves one,
	// and before the collected rows can be adopted into it.
	handlers.EnsureDefaultCluster()
	db.BackfillCollectedCluster()

	// The scan pool and the vulnerability database come up before anything can
	// enqueue work: a scan that starts before the first database download would
	// either fail or fetch its own copy, which is what the shared cache exists
	// to avoid.
	handlers.StartScanWorkers()

	go func() {
		// Trivy's database is fetched centrally, on a schedule of its own, so
		// no scan pays the download and a rescan of untouched code still
		// reflects CVEs published since the last pass.
		interval := 6 * time.Hour
		if v := os.Getenv("TRIVY_DB_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
			}
		}
		handlers.UpdateTrivyDB()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			handlers.UpdateTrivyDB()
		}
	}()

	go func() {
		// Findings go stale on their own: a CVE published today applies to an
		// image nobody has touched. The pass only enqueues -- the worker pool
		// decides how fast the queue actually drains.
		interval := 1 * time.Hour
		if v := os.Getenv("RESCAN_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
			}
		}
		time.Sleep(2 * time.Minute) // let the database download finish first
		handlers.PollRescans()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			handlers.PollRescans()
		}
	}()

	go func() {
		// Workload uptime and change history, read from the Kubernetes apps API.
		// ArgoCD is used only to deploy applications, never to observe them.
		interval := 5 * time.Minute
		if v := os.Getenv("WORKLOAD_MONITORING_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
			}
		}
		time.Sleep(10 * time.Second) // wait for startup
		handlers.PollWorkloads()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			handlers.PollWorkloads()
		}
	}()

	go func() {
		// Pods are sampled more often than apps: metrics-server has no history
		// of its own, so the resolution of the series is the poll interval.
		interval := 2 * time.Minute
		if v := os.Getenv("POD_MONITORING_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
			}
		}
		time.Sleep(20 * time.Second) // wait for startup
		handlers.PollPodMetrics()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			handlers.PollPodMetrics()
		}
	}()

	go func() {
		time.Sleep(30 * time.Second) // wait for startup
		handlers.PollNodeAlerts()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			handlers.PollNodeAlerts()
		}
	}()

	go func() {
		// The service map is rebuilt from what the cluster declares, so it only
		// changes when something is deployed -- a slower interval than the
		// metric pollers is enough, and each pass lists every workload.
		interval := 10 * time.Minute
		if v := os.Getenv("TOPOLOGY_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
			}
		}
		time.Sleep(40 * time.Second) // wait for startup
		handlers.PollTopology()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			handlers.PollTopology()
		}
	}()

	go func() {
		// Application-level errors: a workload can serve 500s with every pod
		// Ready, so this runs whether or not the pod pollers found anything.
		// It reads a fixed window back on each pass and rewrites whole buckets,
		// so the interval only controls freshness, never accuracy.
		interval := 2 * time.Minute
		if v := os.Getenv("APP_ERROR_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
			}
		}
		time.Sleep(50 * time.Second) // wait for startup
		handlers.PollAppErrors()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			handlers.PollAppErrors()
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
	api.Post("/repositories/preflight", handlers.PreflightRepository)
	api.Post("/repositories/import", handlers.ImportRepository)
	api.Post("/repositories/import-project", handlers.ImportProject)
	api.Get("/repositories", handlers.ListRepositories)
	api.Delete("/repositories/:name", handlers.DeleteRepository)
	api.Get("/repositories/:name/src", handlers.GetRepositorySrc)
	api.Put("/repositories/:name/src", handlers.CommitFileEdit)
	api.Get("/repositories/:name/branches", handlers.GetRepositoryBranches)
	api.Get("/repositories/:name/commits", handlers.GetRepositoryCommits)
	api.Get("/repositories/:name/pipelines", handlers.GetRepositoryPipelines)
	api.Post("/repositories/:name/pipelines/trigger", handlers.TriggerPipeline)
	api.Post("/repositories/:name/pipelines/:pipeline_uuid/stop", handlers.StopPipeline)
	api.Get("/repositories/:name/pipelines/:pipeline_uuid/steps", handlers.GetPipelineSteps)
	api.Get("/repositories/:name/pipelines/:pipeline_uuid/steps/:step_uuid/log", handlers.GetStepLog)
	api.Post("/repositories/:name/scan", handlers.RunTrivyScan)
	api.Get("/repositories/:name/scan-history", handlers.GetScanHistory)
	api.Post("/repositories/:name/review", handlers.ReviewFile)
	api.Post("/repositories/:name/analyze", handlers.AnalyzeRepo)
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

	api.Get("/monitoring/nodes", handlers.GetNodeStatus)
	api.Get("/monitoring/nodes/pods", handlers.GetNodePods)
	api.Get("/monitoring/pods", handlers.GetPodStatus)
	api.Get("/monitoring/pods/history", handlers.GetPodHistory)
	api.Get("/monitoring/pods/problems", handlers.GetPodProblems)
	api.Get("/monitoring/services/problems", handlers.GetServiceProblems)
	api.Get("/monitoring/services/errors", handlers.GetServiceErrorSeries)
	api.Get("/monitoring/services/log-errors", handlers.GetLogErrors)

	api.Get("/kubernetes/topology", handlers.GetTopology)
	api.Post("/kubernetes/topology/refresh", handlers.RefreshTopology)

	api.Get("/kubernetes/workloads", handlers.GetWorkloads)
	api.Get("/kubernetes/workloads/history", handlers.GetWorkloadHistory)
	api.Get("/kubernetes/namespaces", handlers.ListK8sNamespaceNames)
	api.Get("/kubernetes/resources/:kind", handlers.ListK8sResources)
	api.Get("/kubernetes/manifest/:kind/:name", handlers.GetK8sManifest)
	api.Get("/kubernetes/detail/:kind/:name", handlers.GetK8sResourceDetail)
	api.Get("/kubernetes/cluster-overview", handlers.GetClusterOverview)

	api.Get("/clusters", handlers.ListClusters)
	api.Post("/clusters", handlers.CreateCluster)
	api.Delete("/clusters/:id", handlers.DeleteCluster)

	api.Get("/kubernetes/pods/logs", handlers.GetPodLogs)
	api.Get("/kubernetes/pods/logs/stream", handlers.StreamPodLogs)
	api.Get("/kubernetes/pods/scale-target", handlers.GetPodScaleTarget)
	api.Post("/kubernetes/pods/restart", handlers.RestartPod)
	api.Post("/kubernetes/pods/scale", handlers.ScalePodWorkload)
	api.Delete("/kubernetes/pods", handlers.DeletePod)

	api.Get("/users/me", handlers.GetMe)
	api.Get("/users/me/keys", handlers.GetMyKeys)
	api.Put("/users/me/keys", handlers.SaveMyKeys)
	api.Get("/users", handlers.ListUsers)
	api.Post("/users", handlers.CreateUser)
	api.Delete("/users/:id", handlers.DeleteUser)
	api.Put("/users/:id/role", handlers.UpdateUserRole)
	api.Put("/users/:id/password", handlers.ChangePassword)
	api.Delete("/users/:id/mfa", handlers.ResetUserMFA)

	api.Get("/webhooks", handlers.ListWebhookConfigs)
	api.Post("/webhooks", handlers.CreateWebhookConfig)
	api.Put("/webhooks/:id", handlers.UpdateWebhookConfig)
	api.Delete("/webhooks/:id", handlers.DeleteWebhookConfig)
	api.Post("/webhooks/:id/test", handlers.TestWebhookConfig)
	api.Get("/webhooks/events", func(c *fiber.Ctx) error {
		return c.SendString(handlers.WebhookEventsJSON())
	})

	api.Get("/golden-paths", handlers.ListGoldenPaths)
	api.Post("/golden-paths", handlers.CreateGoldenPath)
	api.Get("/golden-paths/:id", handlers.GetGoldenPath)
	api.Put("/golden-paths/:id", handlers.UpdateGoldenPath)
	api.Delete("/golden-paths/:id", handlers.DeleteGoldenPath)
	api.Post("/repositories/:name/approve", handlers.ApproveRepository)

	api.Post("/secrets/list", handlers.ListSecrets)
	api.Post("/secrets/reveal", handlers.RevealSecretValue)

	api.Get("/audit-logs", handlers.GetAuditLogs)

	api.Get("/groups", handlers.ListGroups)
	api.Post("/groups", handlers.CreateGroup)
	api.Put("/groups/:id", handlers.UpdateGroup)
	api.Delete("/groups/:id", handlers.DeleteGroup)
	api.Post("/groups/:id/members", handlers.AddGroupMember)
	api.Delete("/groups/:id/members/:user_id", handlers.RemoveGroupMember)
	api.Post("/groups/:id/workspaces", handlers.AddGroupWorkspace)
	api.Delete("/groups/:id/workspaces/:workspace_id", handlers.RemoveGroupWorkspace)

	api.Get("/notifications", handlers.ListNotifications)
	api.Post("/notifications", handlers.CreateNotification)
	api.Put("/notifications/:id", handlers.UpdateNotification)
	api.Delete("/notifications/:id", handlers.DeleteNotification)
	api.Post("/notifications/:id/test", handlers.TestNotification)

	log.Fatal(app.Listen(":8080"))
}
