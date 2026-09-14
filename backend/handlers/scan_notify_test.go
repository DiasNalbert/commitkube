package handlers

import (
	"testing"

	"github.com/kubecommit/backend/models"
)

func TestShouldNotify(t *testing.T) {
	prev := models.ScanResult{Critical: 2, High: 5, Medium: 30, Low: 100, ImageCritical: 1, ImageHigh: 4}
	same := map[string]int{"CRITICAL": 2, "HIGH": 5, "MEDIUM": 30, "LOW": 100}
	sameImage := map[string]int{"CRITICAL": 1, "HIGH": 4}

	cases := []struct {
		name        string
		manual      bool
		hadPrevious bool
		counts      map[string]int
		imageCounts map[string]int
		want        bool
	}{
		{
			name: "a person pressed the button", manual: true, hadPrevious: true,
			counts: same, imageCounts: sameImage, want: true,
		},
		{
			name: "first scan of a repository is always news", hadPrevious: false,
			counts: same, imageCounts: sameImage, want: true,
		},
		{
			// The case that matters: this runs every day for every repository.
			name: "scheduled rescan with identical findings stays quiet", hadPrevious: true,
			counts: same, imageCounts: sameImage, want: false,
		},
		{
			name: "fewer findings than before is not an alert", hadPrevious: true,
			counts: map[string]int{"CRITICAL": 0, "HIGH": 1}, imageCounts: map[string]int{"CRITICAL": 0, "HIGH": 0},
			want: false,
		},
		{
			name: "a new critical in the code", hadPrevious: true,
			counts: map[string]int{"CRITICAL": 3, "HIGH": 5}, imageCounts: sameImage, want: true,
		},
		{
			name: "a new high in the image", hadPrevious: true,
			counts: same, imageCounts: map[string]int{"CRITICAL": 1, "HIGH": 5}, want: true,
		},
		{
			// Medium and low churn with every database update; mailing on them
			// would put the whole estate back in the inbox daily.
			name: "more mediums and lows alone do not mail", hadPrevious: true,
			counts:      map[string]int{"CRITICAL": 2, "HIGH": 5, "MEDIUM": 300, "LOW": 900},
			imageCounts: sameImage, want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldNotify(tc.manual, tc.hadPrevious, prev, tc.counts, tc.imageCounts)
			if got != tc.want {
				t.Fatalf("shouldNotify = %v, want %v", got, tc.want)
			}
		})
	}
}
