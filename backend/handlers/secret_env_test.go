package handlers

import "testing"

// A value pasted into a shell truncates at the first space if it is not
// quoted, which fails later as an authentication error nobody traces back to
// a copy button.
func TestEnvLineQuotesWhatWouldBreak(t *testing.T) {
	cases := []struct{ key, value, want string }{
		{"DB_USER", "titan", "DB_USER=titan"},
		{"URL", "https://host:5432/db?a=1", "URL=https://host:5432/db?a=1"},

		{"PASS", "two words", `PASS="two words"`},
		{"PASS", `has"quote`, `PASS="has\"quote"`},
		{"PASS", `back\slash`, `PASS="back\\slash"`},
		{"PASS", "dollar$sign", `PASS="dollar\$sign"`},
		{"PASS", "tick`cmd`", "PASS=\"tick\\`cmd\\`\""},
		{"KEY", "line1\nline2", `KEY="line1\nline2"`},
		{"PASS", "hash#comment", `PASS="hash#comment"`},
	}
	for _, tc := range cases {
		if got := formatEnvLine(tc.key, tc.value); got != tc.want {
			t.Errorf("formatEnvLine(%q, %q)\n got %s\nwant %s", tc.key, tc.value, got, tc.want)
		}
	}
}
