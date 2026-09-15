package handlers

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// useTestDB points the package at a throwaway database carrying only the
// observability tables, so the reconciliation can be exercised for real rather
// than mocked -- the interesting bugs here are in what gets written.
func useTestDB(t *testing.T) {
	t.Helper()
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })

	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "errors.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := gdb.AutoMigrate(
		&models.ErrorWindow{}, &models.DependencyFailure{},
		&models.ServiceProblem{}, &models.ServiceNode{}, &models.LogErrorGroup{},
		&models.NotificationConfig{}, // the problem opener notifies in a goroutine
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_sp_open ON service_problems (namespace, workload, kind) WHERE closed_at IS NULL")
	db.DB = gdb
}

func TestParseNginxAccess(t *testing.T) {
	line := `10.42.0.1 - - [11/Sep/2026:12:00:00 +0000] "GET /checkout?id=9 HTTP/1.1" 502 150 ` +
		`"-" "curl/8.5.0" 123 0.004 [shop-checkout-80] [] 10.1.2.3:8080 0 0.004 502 abc123`

	up, status, path, ok := parseNginxAccess(line)
	if !ok {
		t.Fatal("expected the line to parse")
	}
	if up != "shop-checkout-80" {
		t.Errorf("upstream = %q, want shop-checkout-80", up)
	}
	if status != 502 {
		t.Errorf("status = %d, want 502", status)
	}
	// The query string must be dropped, or one path per caller ends up in the
	// top-path tally and none of them is ever the top.
	if path != "/checkout" {
		t.Errorf("path = %q, want /checkout", path)
	}
}

func TestParseNginxAccessRejectsNonAccessLines(t *testing.T) {
	// Controllers write their own operational logs to the same stream.
	for _, line := range []string{
		`I0911 12:00:00.123456       7 controller.go:190] "Configuration changes detected"`,
		``,
		`some plain text`,
	} {
		if _, _, _, ok := parseAccessLine(line); ok {
			t.Errorf("line parsed as an access log entry but should not have: %q", line)
		}
	}
}

func TestParseTraefikAccess(t *testing.T) {
	line := `{"ServiceName":"shop-checkout-80@kubernetes","DownstreamStatus":503,"RequestPath":"/pay?x=1"}`
	up, status, path, ok := parseTraefikAccess(line)
	if !ok {
		t.Fatal("expected the JSON line to parse")
	}
	if up != "shop-checkout-80@kubernetes" || status != 503 || path != "/pay" {
		t.Errorf("got (%q, %d, %q)", up, status, path)
	}
}

// The upstream name is "<namespace>-<service>-<port>" and both halves may
// contain dashes, so splitting on them picks the wrong workload. The index has
// to resolve by longest known prefix instead.
func TestUpstreamIndexResolvesAmbiguousNames(t *testing.T) {
	useTestDB(t)
	db.DB.Create(&models.ServiceNode{
		ClusterID: testClusterID,
		Namespace: "shop-prod", Kind: "Deployment", Name: "checkout",
		Services: "checkout-api",
	})
	db.DB.Create(&models.ServiceNode{
		ClusterID: testClusterID,
		Namespace: "shop", Kind: "Deployment", Name: "prod-checkout",
		Services: "prod-checkout",
	})

	ix := buildUpstreamIndex(testClusterID)

	ref := ix.resolve("shop-prod-checkout-api-8080")
	if ref.Name != "checkout" || ref.Namespace != "shop-prod" {
		t.Errorf("resolved to %+v, want shop-prod/checkout", ref)
	}
	if got := ix.resolve("shop-prod-checkout-80@kubernetes"); got.Name != "prod-checkout" {
		t.Errorf("traefik-qualified name resolved to %+v, want prod-checkout", got)
	}
	if got := ix.resolve("upstream-default-backend"); !got.empty() {
		t.Errorf("unknown upstream resolved to %+v, want no match", got)
	}
}

func TestIsErrorLogLine(t *testing.T) {
	errors := []string{
		`2026-09-11 ERROR could not reach payment provider`,
		`{"level":"error","msg":"timeout"}`,
		`time=... level=fatal msg="bye"`,
		`panic: runtime error: invalid memory address`,
		`Traceback (most recent call last):`,
	}
	for _, line := range errors {
		if !isErrorLogLine(line) {
			t.Errorf("expected an error line: %q", line)
		}
	}

	// A metric name and a URL path both contain the token but report nothing.
	notErrors := []string{
		`http_ERRORS_TOTAL 4`,
		`GET /error-codes 200`,
		`INFO request completed`,
		`level=info msg="no errors"`,
	}
	for _, line := range notErrors {
		if isErrorLogLine(line) {
			t.Errorf("did not expect an error line: %q", line)
		}
	}
}

// Attribution has three outcomes and the difference between them is the whole
// point of the feature: "unknown" must never be reported as "self", because
// that blames the application for data nobody collected.
func TestAttributeCauseWithoutTrafficLayerIsUnknown(t *testing.T) {
	useTestDB(t)
	now := time.Now()
	got := attributeCause(testClusterID, workloadRef{"prod", "Deployment", "checkout"},
		now.Add(-15*time.Minute), now)
	if got.Kind != "unknown" {
		t.Fatalf("cause = %q, want unknown when no dependency data exists", got.Kind)
	}
}

func TestAttributeCauseNamesTheFailingDependency(t *testing.T) {
	useTestDB(t)
	bucket := bucketOf(time.Now())

	// A healthy in-cluster dependency alongside a third party that is down.
	db.DB.Create(&models.DependencyFailure{
		ClusterID: testClusterID,
		BucketAt:  bucket, Source: "ebpf",
		SrcNamespace: "prod", SrcKind: "Deployment", SrcName: "checkout",
		DstNamespace: "prod", DstKind: "Deployment", DstName: "postgres",
		Attempts: 400,
	})
	db.DB.Create(&models.DependencyFailure{
		ClusterID: testClusterID,
		BucketAt:  bucket, Source: "ebpf",
		SrcNamespace: "prod", SrcKind: "Deployment", SrcName: "checkout",
		DstKind: "External", DstName: "api.vendor.com", DstHost: "api.vendor.com",
		Attempts: 120, ConnTimeout: 90, ConnRefused: 18,
	})

	got := attributeCause(testClusterID, workloadRef{"prod", "Deployment", "checkout"},
		bucket.Add(-10*time.Minute), bucket.Add(time.Minute))
	if got.Kind != "dependency" {
		t.Fatalf("cause = %q, want dependency", got.Kind)
	}
	if got.Name != "api.vendor.com" {
		t.Errorf("blamed %q, want api.vendor.com", got.Name)
	}
	if !strings.Contains(got.Detail, "108 of 120") {
		t.Errorf("detail does not carry the failure counts: %q", got.Detail)
	}
}

func TestAttributeCauseIsSelfWhenDependenciesAnswer(t *testing.T) {
	useTestDB(t)
	bucket := bucketOf(time.Now())
	db.DB.Create(&models.DependencyFailure{
		ClusterID: testClusterID,
		BucketAt:  bucket, Source: "ebpf",
		SrcNamespace: "prod", SrcKind: "Deployment", SrcName: "checkout",
		DstNamespace: "prod", DstKind: "Deployment", DstName: "postgres",
		Attempts: 400,
	})

	got := attributeCause(testClusterID, workloadRef{"prod", "Deployment", "checkout"},
		bucket.Add(-10*time.Minute), bucket.Add(time.Minute))
	if got.Kind != "self" {
		t.Fatalf("cause = %q, want self when every call completed", got.Kind)
	}
}

// A workload whose pods are all Ready but which answers 5xx is the case this
// feature exists for, so it is worth asserting end to end over the database.
func TestEvaluateAndReconcileOpensThenClosesAProblem(t *testing.T) {
	useTestDB(t)
	now := time.Now()
	bucket := bucketOf(now)

	db.DB.Create(&models.ErrorWindow{
		ClusterID: testClusterID,
		BucketAt:  bucket, Namespace: "prod", WorkloadKind: "Deployment",
		Workload: "checkout", Source: "ingress",
		Requests: 200, Status5xx: 60, TopStatus: "502 x60", TopPath: "/pay",
	})
	db.DB.Create(&models.DependencyFailure{
		ClusterID: testClusterID,
		BucketAt:  bucket, Source: "ebpf",
		SrcNamespace: "prod", SrcKind: "Deployment", SrcName: "checkout",
		DstKind: "External", DstName: "api.vendor.com", DstHost: "api.vendor.com",
		Attempts: 60, ConnTimeout: 60,
	})

	reconcileServiceProblems(testClusterID, evaluateWindows(testClusterID, now), now)

	var open []models.ServiceProblem
	db.DB.Where("closed_at IS NULL AND kind = ?", "http_5xx").Find(&open)
	if len(open) != 1 {
		t.Fatalf("got %d open http_5xx problems, want 1", len(open))
	}
	p := open[0]
	if p.Severity != "critical" {
		t.Errorf("severity = %q, want critical at a 30%% error rate", p.Severity)
	}
	if p.CauseKind != "dependency" || p.CauseName != "api.vendor.com" {
		t.Errorf("cause = %s/%s, want dependency/api.vendor.com", p.CauseKind, p.CauseName)
	}

	// A second pass over the same data accumulates rather than duplicating.
	reconcileServiceProblems(testClusterID, evaluateWindows(testClusterID, now), now)
	db.DB.Where("closed_at IS NULL AND kind = ?", "http_5xx").Find(&open)
	if len(open) != 1 {
		t.Fatalf("second pass produced %d open problems, want 1", len(open))
	}
	if open[0].Occurrences != 2 {
		t.Errorf("occurrences = %d, want 2", open[0].Occurrences)
	}

	// Once the errors stop, the next pass must close it.
	db.DB.Where("1 = 1").Delete(&models.ErrorWindow{})
	db.DB.Where("1 = 1").Delete(&models.DependencyFailure{})
	later := now.Add(errorBucket)
	reconcileServiceProblems(testClusterID, evaluateWindows(testClusterID, later), later)

	db.DB.Where("closed_at IS NULL").Find(&open)
	if len(open) != 0 {
		t.Fatalf("got %d problems still open after the errors stopped", len(open))
	}
}

// Below the minimum request count a single failed request is 100% of traffic.
// Opening a critical incident on that is how an error-rate alert earns its
// reputation for crying wolf.
func TestEvaluateIgnoresLowTraffic(t *testing.T) {
	useTestDB(t)
	now := time.Now()
	db.DB.Create(&models.ErrorWindow{
		ClusterID: testClusterID,
		BucketAt:  bucketOf(now), Namespace: "prod", WorkloadKind: "Deployment",
		Workload: "batch", Source: "ingress", Requests: 3, Status5xx: 3,
	})

	if got := evaluateWindows(testClusterID, now); len(got) != 0 {
		t.Fatalf("got %d problems from 3 requests, want 0", len(got))
	}
}

// Grouping is what turns a log into a catalogue. A thousand failures that
// differ only in an order id have to collapse to one entry with a count, or
// the list is just the log with extra steps.
func TestLogTemplateCollapsesVariableParts(t *testing.T) {
	a := `2026-09-11T09:14:02.512Z ERROR run 48213 failed for document 9f1c2b44-1e77-4a55-9c31-2b6a0d8e1f00 at https://portal.vendor.com/nfe/48213`
	b := `2026-09-11T11:47:55.003Z ERROR run 48999 failed for document 3ab47e10-9d22-4c81-bb03-77aa1e6c5d92 at https://portal.vendor.com/nfe/48999`

	if logTemplate(a) != logTemplate(b) {
		t.Fatalf("two runs of the same failure produced different templates:\n%q\n%q",
			logTemplate(a), logTemplate(b))
	}
	if fingerprint(logTemplate(a)) != fingerprint(logTemplate(b)) {
		t.Error("templates matched but fingerprints did not")
	}

	// A genuinely different failure must not be folded into the same group.
	c := `2026-09-11T11:47:55.003Z ERROR login form not found on page`
	if fingerprint(logTemplate(a)) == fingerprint(logTemplate(c)) {
		t.Error("unrelated errors collapsed into one group")
	}
}

// This is the distinction the whole feature turns on for an RPA: the site was
// down, versus the automation broke.
func TestClassifyLogErrorSeparatesThirdPartyFromApp(t *testing.T) {
	cases := []struct {
		line, want string
	}{
		{`Error: net::ERR_NAME_NOT_RESOLVED at https://portal.vendor.com`, "dependency_unreachable"},
		{`requests.exceptions.ConnectionError: HTTPSConnectionPool(host='api.vendor.com', port=443)`, "dependency_unreachable"},
		{`Error: connect ECONNREFUSED 10.1.2.3:443`, "dependency_unreachable"},
		{`java.net.UnknownHostException: portal.vendor.com`, "dependency_unreachable"},
		{`TimeoutError: Navigation timeout of 30000 ms exceeded`, "dependency_timeout"},
		{`net::ERR_CONNECTION_TIMED_OUT`, "dependency_timeout"},
		{`Received status code 503 Service Unavailable from https://api.vendor.com/v1`, "dependency_http"},
		{`selenium.common.exceptions.NoSuchElementException: Unable to locate element: #cpf`, "app_exception"},
		{`Traceback (most recent call last):`, "app_exception"},
		{`ERROR something went sideways`, "unknown"},
	}
	for _, tc := range cases {
		if got := classifyLogError(tc.line); got != tc.want {
			t.Errorf("classify(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestExtractTarget(t *testing.T) {
	cases := []struct {
		line, want string
	}{
		{`net::ERR_NAME_NOT_RESOLVED at https://portal.vendor.com/nfe/list`, "portal.vendor.com"},
		{`HTTPSConnectionPool(host='api.vendor.com', port=443): Read timed out`, "api.vendor.com"},
		{`java.net.UnknownHostException: sefaz.rs.gov.br`, "sefaz.rs.gov.br"},
		// A stack trace is full of dotted names that are not hosts.
		{`  File "/app/robot/main.py", line 42, in run`, ""},
		{`TypeError in app.service.ts`, ""},
		// No host named means no host attributed, rather than a guess.
		{`TimeoutError: Navigation timeout of 30000 ms exceeded`, ""},
	}
	for _, tc := range cases {
		if got := extractTarget(tc.line); got != tc.want {
			t.Errorf("extractTarget(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

// The RPA case end to end: a nightly robot fails because the site it drives is
// down. No ingress, no eBPF, no instrumentation -- only the pod's own log.
func TestRPAFailureIsBlamedOnTheThirdParty(t *testing.T) {
	useTestDB(t)
	now := time.Now()
	bucket := bucketOf(now)
	ref := workloadRef{"automation", "CronJob", "rpa-nfe"}

	line := `ERROR run failed: net::ERR_CONNECTION_TIMED_OUT at https://portal.vendor.com/nfe`
	db.DB.Create(&models.LogErrorGroup{
		ClusterID: testClusterID,
		BucketAt:  bucket, Namespace: ref.Namespace, WorkloadKind: ref.Kind, Workload: ref.Name,
		Fingerprint: fingerprint(logTemplate(line)), Template: logTemplate(line),
		Class: classifyLogError(line), Target: extractTarget(line),
		Count: 3, Sample: line, LastPod: "rpa-nfe-29284560-x7k2",
	})
	// Only three error lines across fifteen minutes: far below the per-minute
	// rate a continuously serving workload is held to.
	db.DB.Create(&models.ErrorWindow{
		ClusterID: testClusterID,
		BucketAt:  bucket, Namespace: ref.Namespace, WorkloadKind: ref.Kind,
		Workload: ref.Name, Source: "logs", ErrorLogs: 3,
	})

	found := evaluateWindows(testClusterID, now)
	if len(found) != 1 {
		t.Fatalf("got %d problems, want 1 -- a batch workload must not be held to a per-minute rate", len(found))
	}
	d := found[0]
	if d.Cause.Kind != "dependency" {
		t.Errorf("cause kind = %q, want dependency", d.Cause.Kind)
	}
	if d.Cause.Source != "logs" {
		t.Errorf("cause source = %q, want logs", d.Cause.Source)
	}
	if d.Cause.Host != "portal.vendor.com" {
		t.Errorf("blamed %q, want portal.vendor.com", d.Cause.Host)
	}
	if !strings.Contains(d.Title, "portal.vendor.com") {
		t.Errorf("title does not name the third party: %q", d.Title)
	}

	reconcileServiceProblems(testClusterID, found, now)
	var open []models.ServiceProblem
	db.DB.Where("closed_at IS NULL").Find(&open)
	if len(open) != 1 || open[0].CauseSource != "logs" {
		t.Fatalf("problem not stored with the inferred cause: %+v", open)
	}
}

// A broken automation must stay the automation's problem. If a selector failure
// could borrow a hostname from elsewhere in the log, every bug in the robot
// would be filed against the vendor.
func TestBrokenAutomationIsNotBlamedOnTheThirdParty(t *testing.T) {
	useTestDB(t)
	now := time.Now()
	bucket := bucketOf(now)
	ref := workloadRef{"automation", "CronJob", "rpa-nfe"}

	line := `selenium.common.exceptions.NoSuchElementException: Unable to locate element: #cpf`
	db.DB.Create(&models.LogErrorGroup{
		ClusterID: testClusterID,
		BucketAt:  bucket, Namespace: ref.Namespace, WorkloadKind: ref.Kind, Workload: ref.Name,
		Fingerprint: fingerprint(logTemplate(line)), Template: logTemplate(line),
		Class: classifyLogError(line), Target: extractTarget(line),
		Count: 2, Sample: line,
	})
	db.DB.Create(&models.ErrorWindow{
		ClusterID: testClusterID,
		BucketAt:  bucket, Namespace: ref.Namespace, WorkloadKind: ref.Kind,
		Workload: ref.Name, Source: "logs", ErrorLogs: 2,
	})

	found := evaluateWindows(testClusterID, now)
	if len(found) != 1 {
		t.Fatalf("got %d problems, want 1", len(found))
	}
	if got := found[0].Cause.Kind; got != "unknown" {
		t.Errorf("cause = %q, want unknown: nothing observed the calls and the log blamed nobody", got)
	}
}

// Measurement beats inference: when the eBPF layer watched the calls, its
// verdict is the one reported.
func TestObservedCauseWinsOverInferredCause(t *testing.T) {
	useTestDB(t)
	now := time.Now()
	bucket := bucketOf(now)
	ref := workloadRef{"prod", "Deployment", "checkout"}

	line := `ERROR net::ERR_CONNECTION_TIMED_OUT at https://stale.vendor.com`
	db.DB.Create(&models.LogErrorGroup{
		ClusterID: testClusterID,
		BucketAt:  bucket, Namespace: ref.Namespace, WorkloadKind: ref.Kind, Workload: ref.Name,
		Fingerprint: "deadbeef", Template: logTemplate(line),
		Class: classifyLogError(line), Target: extractTarget(line), Count: 50, Sample: line,
	})
	db.DB.Create(&models.DependencyFailure{
		ClusterID: testClusterID,
		BucketAt:  bucket, Source: "ebpf",
		SrcNamespace: ref.Namespace, SrcKind: ref.Kind, SrcName: ref.Name,
		DstKind: "External", DstName: "real.vendor.com", DstHost: "real.vendor.com",
		Attempts: 10, ConnRefused: 10,
	})

	got := attributeCause(testClusterID, ref, bucket.Add(-10*time.Minute), bucket.Add(time.Minute))
	if got.Source != "ebpf" || got.Host != "real.vendor.com" {
		t.Fatalf("got %s/%s, want ebpf/real.vendor.com", got.Source, got.Host)
	}
}

// A third party that accepts the connection and answers 503 fails at L7, where
// the L4 layer sees nothing wrong. The log has to be allowed to override a
// clean traffic reading, or this failure is reported as the caller's own bug.
func TestLayer7FailureIsNotReportedAsSelf(t *testing.T) {
	useTestDB(t)
	now := time.Now()
	bucket := bucketOf(now)
	ref := workloadRef{"prod", "Deployment", "checkout"}

	db.DB.Create(&models.DependencyFailure{
		ClusterID: testClusterID,
		BucketAt:  bucket, Source: "ebpf",
		SrcNamespace: ref.Namespace, SrcKind: ref.Kind, SrcName: ref.Name,
		DstKind: "External", DstName: "api.vendor.com", DstHost: "api.vendor.com",
		Attempts: 500, // every connection completed
	})
	line := `ERROR received status code 503 Service Unavailable from https://api.vendor.com/v1/pay`
	db.DB.Create(&models.LogErrorGroup{
		ClusterID: testClusterID,
		BucketAt:  bucket, Namespace: ref.Namespace, WorkloadKind: ref.Kind, Workload: ref.Name,
		Fingerprint: fingerprint(logTemplate(line)), Template: logTemplate(line),
		Class: classifyLogError(line), Target: extractTarget(line), Count: 120, Sample: line,
	})

	got := attributeCause(testClusterID, ref, bucket.Add(-10*time.Minute), bucket.Add(time.Minute))
	if got.Kind != "dependency" {
		t.Fatalf("cause = %q, want dependency: L4 was clean but the vendor answered 503", got.Kind)
	}
	if got.Source != "logs" || got.Host != "api.vendor.com" {
		t.Errorf("got %s/%s, want logs/api.vendor.com", got.Source, got.Host)
	}
}

// A CronJob names each run after the minute it fired. Rolling the Job up to the
// CronJob is what lets a nightly failure accumulate instead of appearing as a
// new workload every night.
func TestWorkloadForPodRollsJobUpToCronJob(t *testing.T) {
	controller := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rpa-nfe-29284560-x7k2",
			Namespace: "automation",
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Job", Name: "rpa-nfe-29284560", Controller: &controller},
			},
		},
	}
	jobs := map[string]workloadRef{
		"automation/rpa-nfe-29284560": {"automation", "CronJob", "rpa-nfe"},
	}

	got := workloadForPod(pod, jobs)
	if got.Kind != "CronJob" || got.Name != "rpa-nfe" {
		t.Fatalf("got %+v, want automation/CronJob/rpa-nfe", got)
	}

	// A standalone Job has no CronJob above it and keeps its own identity.
	if got := workloadForPod(pod, map[string]workloadRef{}); got.Name != "rpa-nfe-29284560" {
		t.Errorf("standalone job resolved to %+v", got)
	}
}

// An in-house automation logs in the language its author writes in. With an
// English-only token list nothing downstream ever runs for those workloads --
// no count, no group, no problem, no alert -- and the result looks exactly like
// a healthy cluster.
func TestIsErrorLogLineRecognisesPortuguese(t *testing.T) {
	errors := []string{
		`2026-09-11 10:32:01 ERRO ao acessar o portal da SEFAZ`,
		`[FALHA] robô encerrado sem concluir`,
		`processo FALHOU na etapa de login`,
		`EXCEÇÃO não tratada durante a execução`,
		`não foi possível conectar ao servidor`,
	}
	for _, line := range errors {
		if !isErrorLogLine(line) {
			t.Errorf("expected an error line: %q", line)
		}
	}

	notErrors := []string{
		`INFO nenhum erro encontrado`,
		`processando lote sem falhas`,
	}
	for _, line := range notErrors {
		if isErrorLogLine(line) {
			t.Errorf("did not expect an error line: %q", line)
		}
	}
}

// "ERRO" is a prefix of "ERROR". The boundary check has to stop the shorter
// token from matching inside the longer one, or every English error line is
// counted under the Portuguese token and the classification drifts.
func TestPortugueseTokenDoesNotMatchInsideEnglishWord(t *testing.T) {
	for _, line := range []string{`http_ERRORS_TOTAL 4`, `GET /erros-conhecidos 200`} {
		if isErrorLogLine(line) {
			t.Errorf("did not expect an error line: %q", line)
		}
	}
	// The English word still matches on its own.
	if !isErrorLogLine(`ERROR upstream timed out`) {
		t.Error("ERROR should still be recognised")
	}
}

func TestClassifyLogErrorHandlesPortugueseWrappers(t *testing.T) {
	cases := []struct {
		line, want string
	}{
		{`ERRO: não foi possível conectar ao https://portal.vendor.com`, "dependency_unreachable"},
		{`FALHA: o portal está fora do ar`, "dependency_unreachable"},
		{`ERRO: tempo limite excedido ao aguardar https://sefaz.rs.gov.br`, "dependency_timeout"},
	}
	for _, tc := range cases {
		if got := classifyLogError(tc.line); got != tc.want {
			t.Errorf("classify(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}
