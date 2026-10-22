package handlers

import (
	"fmt"
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// An upgraded database holds a stored report per repository and no finding
// rows. The backfill turns them into rows on startup; this measures how long
// that takes for an estate of realistic size.
func TestBackfillScale(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	useScanDB(t)
	const repos, perRepo = 40, 1500
	for r := 0; r < repos; r++ {
		var rep TrivyReport
		tgt := TrivyTarget{Target: "alpine 3.18"}
		for i := 0; i < perRepo; i++ {
			tgt.Vulnerabilities = append(tgt.Vulnerabilities, TrivyVuln{VulnerabilityID: fmt.Sprintf("CVE-2024-%05d", i), PkgName: fmt.Sprintf("pkg%d", i%300), InstalledVersion: "1", Severity: "HIGH"})
		}
		rep.Results = []TrivyTarget{tgt}
		db.DB.Create(&models.ScanResult{RepoName: fmt.Sprintf("repo-%d", r), ImageReport: marshalReport(rep)})
	}
	start := time.Now()
	BackfillScanFindings()
	el := time.Since(start)
	var n int64
	db.DB.Model(&models.ScanFinding{}).Count(&n)
	t.Logf("backfill: %d repos x %d findings = %d rows in %v (%.0f rows/s)", repos, perRepo, n, el, float64(n)/el.Seconds())
	if n != repos*perRepo {
		t.Fatalf("rows = %d", n)
	}

	// A rescan of an unchanged report: the common case, every hour.
	var r0 models.ScanResult
	db.DB.First(&r0)
	var rep TrivyReport
	_ = unmarshalReport(r0.ImageReport, &rep)
	start = time.Now()
	if _, err := reconcileFindings(r0.RepoName, FindingDomainImage, findingsFromReport(rep, FindingDomainImage), time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Logf("rescan of one unchanged repo (%d findings): %v", perRepo, time.Since(start))
}
