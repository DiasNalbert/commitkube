package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDockerfile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBaseImageFromDockerfile(t *testing.T) {
	cases := []struct {
		name, body, want, wantErr string
	}{
		{
			name: "single stage",
			body: "FROM alpine:3.20\nRUN apk add curl\n",
			want: "alpine:3.20",
		},
		{
			// Only the last stage ships: reporting the builder would describe a
			// toolchain that never reaches production.
			name: "multi stage reports the final stage",
			body: "FROM golang:1.22 AS builder\nRUN go build\n\nFROM alpine:3.20\nCOPY --from=builder /app /app\n",
			want: "alpine:3.20",
		},
		{
			name: "final stage referencing an earlier alias",
			body: "FROM debian:12 AS base\nFROM base AS runtime\n",
			want: "debian:12",
		},
		{
			name: "ARG with a default is substituted",
			body: "ARG VERSION=3.20\nFROM alpine:${VERSION}\n",
			want: "alpine:3.20",
		},
		{
			name: "platform flag is skipped",
			body: "FROM --platform=linux/amd64 alpine:3.20 AS x\n",
			want: "alpine:3.20",
		},
		{
			name:    "scratch has nothing to scan",
			body:    "FROM golang:1.22 AS b\nFROM scratch\nCOPY --from=b /app /app\n",
			wantErr: "scratch",
		},
		{
			name:    "ARG without a default cannot be resolved",
			body:    "ARG REGISTRY\nFROM ${REGISTRY}/app:1\n",
			wantErr: "build argument",
		},
		{
			name:    "no FROM at all",
			body:    "# empty\nRUN true\n",
			wantErr: "no FROM",
		},
		{
			name: "comments and blank lines are ignored",
			body: "# comment\n\n   FROM   ubuntu:22.04   \n",
			want: "ubuntu:22.04",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeDockerfile(t, t.TempDir(), "Dockerfile", tc.body)
			got, err := baseImageFromDockerfile(path)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got image %q", tc.wantErr, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveBaseImagePrefersTheRoot(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, filepath.Join("examples", "Dockerfile"), "FROM busybox:1\n")
	writeDockerfile(t, dir, "Dockerfile", "FROM alpine:3.20\n")

	img, file, err := resolveBaseImage(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img != "alpine:3.20" {
		t.Fatalf("got %q, want the root Dockerfile's image", img)
	}
	if file != "Dockerfile" {
		t.Fatalf("got file %q, want Dockerfile", file)
	}
}

func TestFindDockerfilesSkipsVendoredTrees(t *testing.T) {
	dir := t.TempDir()
	writeDockerfile(t, dir, filepath.Join("node_modules", "x", "Dockerfile"), "FROM busybox:1\n")
	writeDockerfile(t, dir, filepath.Join("vendor", "y", "Dockerfile"), "FROM busybox:1\n")
	writeDockerfile(t, dir, "Dockerfile.prod", "FROM alpine:3.20\n")

	files := findDockerfiles(dir)
	if len(files) != 1 {
		t.Fatalf("expected only the top-level Dockerfile, got %v", files)
	}
}
