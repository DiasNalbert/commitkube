package main

import (
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/handlers"
	"github.com/kubecommit/backend/middleware"
)

// Routing and policy on the same line, on purpose: a new endpoint cannot be
// added without stating who may call it, and AuditRoutePermissions refuses to
// start the server if one slips through anyway. Four role checks spread across
// a hundred routes is how the previous arrangement left everything added since
// open to any account.
func guarded(r fiber.Router, method, path, perm string, h fiber.Handler) {
	handlers.Declare(method, path, perm)
	switch method {
	case "GET":
		r.Get(path, handlers.Requires(perm), h)
	case "POST":
		r.Post(path, handlers.Requires(perm), h)
	case "PUT":
		r.Put(path, handlers.Requires(perm), h)
	case "DELETE":
		r.Delete(path, handlers.Requires(perm), h)
	case "PATCH":
		r.Patch(path, handlers.Requires(perm), h)
	}
}

func get(r fiber.Router, path, perm string, h fiber.Handler)  { guarded(r, "GET", path, perm, h) }
func post(r fiber.Router, path, perm string, h fiber.Handler) { guarded(r, "POST", path, perm, h) }
func put(r fiber.Router, path, perm string, h fiber.Handler)  { guarded(r, "PUT", path, perm, h) }
func del(r fiber.Router, path, perm string, h fiber.Handler)  { guarded(r, "DELETE", path, perm, h) }

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

	// The public endpoints are the ones worth guessing against: a password, a
	// TOTP code, a stage token. None of them was rate limited, which made
	// guessing free. Per-IP, because an attacker controls the body but not
	// where the packets come from.
	authLimit := limiter.New(limiter.Config{
		Max:        20,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "too many attempts; wait a minute and try again",
			})
		},
	})

	app.Post("/api/auth/login", authLimit, handlers.Login)
	app.Post("/api/auth/verify-mfa", authLimit, handlers.VerifyMFA)
	app.Post("/api/auth/refresh", authLimit, handlers.RefreshTokenHandler)
	app.Post("/api/auth/setup-init", authLimit, handlers.SetupInit)
	app.Post("/api/auth/setup-confirm", authLimit, handlers.SetupConfirm)

	api := app.Group("/api", middleware.AuthRequired())

	post(api, "/repositories", handlers.PermSCMWrite, handlers.CreateRepository)
	post(api, "/repositories/preflight", handlers.PermSCMWrite, handlers.PreflightRepository)
	post(api, "/repositories/import", handlers.PermSCMWrite, handlers.ImportRepository)
	post(api, "/repositories/import-project", handlers.PermSCMWrite, handlers.ImportProject)
	get(api, "/repositories", handlers.PermSCMRead, handlers.ListRepositories)
	del(api, "/repositories/:name", handlers.PermSCMWrite, handlers.DeleteRepository)
	get(api, "/repositories/:name/src", handlers.PermSCMRead, handlers.GetRepositorySrc)
	put(api, "/repositories/:name/src", handlers.PermSCMWrite, handlers.CommitFileEdit)
	get(api, "/repositories/:name/branches", handlers.PermSCMRead, handlers.GetRepositoryBranches)
	get(api, "/repositories/:name/commits", handlers.PermSCMRead, handlers.GetRepositoryCommits)
	get(api, "/repositories/:name/pipelines", handlers.PermSCMRead, handlers.GetRepositoryPipelines)
	post(api, "/repositories/:name/pipelines/trigger", handlers.PermSCMWrite, handlers.TriggerPipeline)
	post(api, "/repositories/:name/pipelines/:pipeline_uuid/stop", handlers.PermSCMWrite, handlers.StopPipeline)
	get(api, "/repositories/:name/pipelines/:pipeline_uuid/steps", handlers.PermSCMRead, handlers.GetPipelineSteps)
	get(api, "/repositories/:name/pipelines/:pipeline_uuid/steps/:step_uuid/log", handlers.PermSCMRead, handlers.GetStepLog)
	post(api, "/repositories/:name/scan", handlers.PermSecurityScan, handlers.RunTrivyScan)
	get(api, "/repositories/:name/scan-history", handlers.PermSecurityRead, handlers.GetScanHistory)
	post(api, "/repositories/:name/review", handlers.PermSCMWrite, handlers.ReviewFile)
	post(api, "/repositories/:name/analyze", handlers.PermSecurityScan, handlers.AnalyzeRepo)
	get(api, "/scan-dashboard", handlers.PermSecurityRead, handlers.GetScanDashboard)
	get(api, "/scan-dashboard/:name", handlers.PermSecurityRead, handlers.GetRepoScanDetail)

	get(api, "/settings", handlers.PermSettingsRead, handlers.GetSettings)
	put(api, "/settings", handlers.PermSettingsWrite, handlers.UpdateSettings)

	get(api, "/smtp", handlers.PermSettingsRead, handlers.GetSMTPConfig)
	put(api, "/smtp", handlers.PermSettingsWrite, handlers.UpdateSMTPConfig)

	get(api, "/templates", handlers.PermTemplateRead, handlers.ListTemplates)
	post(api, "/templates", handlers.PermTemplateWrite, handlers.CreateTemplate)
	put(api, "/templates/:id", handlers.PermTemplateWrite, handlers.UpdateTemplate)
	del(api, "/templates/:id", handlers.PermTemplateWrite, handlers.DeleteTemplate)

	get(api, "/global-vars", handlers.PermSettingsRead, handlers.ListGlobalVars)
	post(api, "/global-vars", handlers.PermSettingsWrite, handlers.CreateGlobalVar)
	put(api, "/global-vars/:id", handlers.PermSettingsWrite, handlers.UpdateGlobalVar)
	del(api, "/global-vars/:id", handlers.PermSettingsWrite, handlers.DeleteGlobalVar)

	get(api, "/workspaces", handlers.PermSCMRead, handlers.ListWorkspaces)
	post(api, "/workspaces", handlers.PermSCMWrite, handlers.CreateWorkspace)
	put(api, "/workspaces/:id", handlers.PermSCMWrite, handlers.UpdateWorkspace)
	del(api, "/workspaces/:id", handlers.PermSCMWrite, handlers.DeleteWorkspace)

	get(api, "/workspaces/:workspace_id/projects", handlers.PermSCMRead, handlers.ListProjects)
	post(api, "/workspaces/:workspace_id/projects", handlers.PermSCMWrite, handlers.CreateProject)
	del(api, "/workspaces/:workspace_id/projects/:id", handlers.PermSCMWrite, handlers.DeleteProject)

	get(api, "/argocd-instances", handlers.PermSettingsRead, handlers.ListArgoCDInstances)
	post(api, "/argocd-instances", handlers.PermSettingsWrite, handlers.CreateArgoCDInstance)
	put(api, "/argocd-instances/:id", handlers.PermSettingsWrite, handlers.UpdateArgoCDInstance)
	del(api, "/argocd-instances/:id", handlers.PermSettingsWrite, handlers.DeleteArgoCDInstance)

	get(api, "/registry-credentials", handlers.PermSettingsRead, handlers.ListRegistryCredentials)
	post(api, "/registry-credentials", handlers.PermSettingsWrite, handlers.CreateRegistryCredential)
	put(api, "/registry-credentials/:id", handlers.PermSettingsWrite, handlers.UpdateRegistryCredential)
	del(api, "/registry-credentials/:id", handlers.PermSettingsWrite, handlers.DeleteRegistryCredential)

	get(api, "/dashboard/summary", handlers.PermSCMRead, handlers.GetDashboardSummary)

	get(api, "/monitoring/nodes", handlers.PermK8sRead, handlers.GetNodeStatus)
	get(api, "/monitoring/nodes/pods", handlers.PermK8sRead, handlers.GetNodePods)
	get(api, "/monitoring/pods", handlers.PermK8sRead, handlers.GetPodStatus)
	get(api, "/monitoring/pods/history", handlers.PermK8sRead, handlers.GetPodHistory)
	get(api, "/monitoring/pods/problems", handlers.PermK8sRead, handlers.GetPodProblems)
	get(api, "/monitoring/services/problems", handlers.PermK8sRead, handlers.GetServiceProblems)
	get(api, "/monitoring/services/errors", handlers.PermK8sRead, handlers.GetServiceErrorSeries)
	get(api, "/monitoring/services/log-errors", handlers.PermK8sRead, handlers.GetLogErrors)

	get(api, "/kubernetes/topology", handlers.PermK8sRead, handlers.GetTopology)
	post(api, "/kubernetes/topology/refresh", handlers.PermK8sRead, handlers.RefreshTopology)

	get(api, "/kubernetes/workloads", handlers.PermK8sRead, handlers.GetWorkloads)
	get(api, "/kubernetes/workloads/history", handlers.PermK8sRead, handlers.GetWorkloadHistory)
	get(api, "/kubernetes/namespaces", handlers.PermK8sRead, handlers.ListK8sNamespaceNames)
	get(api, "/kubernetes/resources/:kind", handlers.PermK8sRead, handlers.ListK8sResources)
	get(api, "/kubernetes/manifest/:kind/:name", handlers.PermK8sRead, handlers.GetK8sManifest)
	get(api, "/kubernetes/detail/:kind/:name", handlers.PermK8sRead, handlers.GetK8sResourceDetail)
	get(api, "/kubernetes/cluster-overview", handlers.PermK8sRead, handlers.GetClusterOverview)
	get(api, "/kubernetes/pod-security", handlers.PermSecurityRead, handlers.GetPodSecurity)

	get(api, "/clusters", handlers.PermK8sRead, handlers.ListClusters)
	post(api, "/clusters", handlers.PermClusterWrite, handlers.CreateCluster)
	del(api, "/clusters/:id", handlers.PermClusterWrite, handlers.DeleteCluster)
	put(api, "/clusters/:id/flags", handlers.PermIAMManage, handlers.UpdateClusterFlags)

	get(api, "/kubernetes/pods/logs", handlers.PermK8sLogsRead, handlers.GetPodLogs)
	get(api, "/kubernetes/pods/logs/stream", handlers.PermK8sLogsRead, handlers.StreamPodLogs)
	get(api, "/kubernetes/pods/scale-target", handlers.PermK8sScale, handlers.GetPodScaleTarget)
	post(api, "/kubernetes/pods/restart", handlers.PermK8sPodDelete, handlers.RestartPod)
	post(api, "/kubernetes/pods/scale", handlers.PermK8sScale, handlers.ScalePodWorkload)
	del(api, "/kubernetes/pods", handlers.PermK8sPodDelete, handlers.DeletePod)

	get(api, "/users/me", handlers.PermSelf, handlers.GetMe)
	get(api, "/users/me/keys", handlers.PermSelf, handlers.GetMyKeys)
	put(api, "/users/me/keys", handlers.PermSelf, handlers.SaveMyKeys)
	get(api, "/users", handlers.PermUserManage, handlers.ListUsers)
	post(api, "/users", handlers.PermUserManage, handlers.CreateUser)
	del(api, "/users/:id", handlers.PermUserManage, handlers.DeleteUser)
	put(api, "/users/:id/role", handlers.PermUserManage, handlers.UpdateUserRole)
	put(api, "/users/:id/password", handlers.PermSelf, handlers.ChangePassword)
	del(api, "/users/:id/mfa", handlers.PermUserManage, handlers.ResetUserMFA)

	get(api, "/webhooks", handlers.PermSettingsRead, handlers.ListWebhookConfigs)
	post(api, "/webhooks", handlers.PermNotifyWrite, handlers.CreateWebhookConfig)
	put(api, "/webhooks/:id", handlers.PermNotifyWrite, handlers.UpdateWebhookConfig)
	del(api, "/webhooks/:id", handlers.PermNotifyWrite, handlers.DeleteWebhookConfig)
	post(api, "/webhooks/:id/test", handlers.PermNotifyWrite, handlers.TestWebhookConfig)
	get(api, "/webhooks/events", handlers.PermSettingsRead, func(c *fiber.Ctx) error {
		return c.SendString(handlers.WebhookEventsJSON())
	})

	get(api, "/golden-paths", handlers.PermTemplateRead, handlers.ListGoldenPaths)
	post(api, "/golden-paths", handlers.PermTemplateWrite, handlers.CreateGoldenPath)
	get(api, "/golden-paths/:id", handlers.PermTemplateRead, handlers.GetGoldenPath)
	put(api, "/golden-paths/:id", handlers.PermTemplateWrite, handlers.UpdateGoldenPath)
	del(api, "/golden-paths/:id", handlers.PermTemplateWrite, handlers.DeleteGoldenPath)
	post(api, "/repositories/:name/approve", handlers.PermSCMApprove, handlers.ApproveRepository)

	post(api, "/secrets/list", handlers.PermK8sSecretsRead, handlers.ListSecrets)
	post(api, "/secrets/reveal", handlers.PermK8sSecretsShow, handlers.RevealSecretValue)
	post(api, "/secrets/reveal-bundle", handlers.PermK8sSecretsShow, handlers.RevealSecretBundle)
	put(api, "/secrets/value", handlers.PermK8sSecretsWrite, handlers.UpdateSecretValue)

	get(api, "/audit-logs", handlers.PermAuditRead, handlers.GetAuditLogs)

	get(api, "/me/permissions", handlers.PermSelf, handlers.GetMyPermissions)
	get(api, "/permissions/catalog", handlers.PermIAMManage, handlers.ListPermissionCatalog)
	get(api, "/permissions/grants", handlers.PermIAMManage, handlers.ListGrants)
	post(api, "/permissions/grants", handlers.PermIAMManage, handlers.GrantPermission)
	del(api, "/permissions/grants", handlers.PermIAMManage, handlers.RevokePermission)
	get(api, "/permissions/scopes", handlers.PermIAMManage, handlers.ListNamespaceScopes)
	post(api, "/permissions/scopes", handlers.PermIAMManage, handlers.AddNamespaceScope)
	del(api, "/permissions/scopes/:id", handlers.PermIAMManage, handlers.RemoveNamespaceScope)
	get(api, "/rbac/preview", handlers.PermIAMManage, handlers.PreviewClusterRBAC)
	post(api, "/rbac/apply", handlers.PermIAMManage, handlers.ApplyClusterRBAC)

	get(api, "/groups", handlers.PermUserManage, handlers.ListGroups)
	post(api, "/groups", handlers.PermUserManage, handlers.CreateGroup)
	put(api, "/groups/:id", handlers.PermUserManage, handlers.UpdateGroup)
	del(api, "/groups/:id", handlers.PermUserManage, handlers.DeleteGroup)
	post(api, "/groups/:id/members", handlers.PermUserManage, handlers.AddGroupMember)
	del(api, "/groups/:id/members/:user_id", handlers.PermUserManage, handlers.RemoveGroupMember)
	post(api, "/groups/:id/workspaces", handlers.PermUserManage, handlers.AddGroupWorkspace)
	del(api, "/groups/:id/workspaces/:workspace_id", handlers.PermUserManage, handlers.RemoveGroupWorkspace)

	get(api, "/notifications", handlers.PermSettingsRead, handlers.ListNotifications)
	post(api, "/notifications", handlers.PermNotifyWrite, handlers.CreateNotification)
	put(api, "/notifications/:id", handlers.PermNotifyWrite, handlers.UpdateNotification)
	del(api, "/notifications/:id", handlers.PermNotifyWrite, handlers.DeleteNotification)
	post(api, "/notifications/:id/test", handlers.PermNotifyWrite, handlers.TestNotification)

	// An API route that declares no permission would be reachable by any
	// account, which is the exact failure this design exists to prevent.
	// Refusing to start is the only moment that mistake is cheap to fix.
	if err := handlers.AuditRoutePermissions(app.GetRoutes(), map[string]bool{
		"/api/auth/login":         true,
		"/api/auth/verify-mfa":    true,
		"/api/auth/refresh":       true,
		"/api/auth/setup-init":    true,
		"/api/auth/setup-confirm": true,
	}); err != nil {
		log.Fatalf("route permission audit failed: %v", err)
	}

	log.Fatal(app.Listen(":8080"))
}
