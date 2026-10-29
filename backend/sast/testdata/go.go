package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/gofiber/fiber/v2"
)

func sqlCases(db *sql.DB, id string, n int) {
	// ruleid: ck-go-sql-built-from-strings
	db.Query("SELECT * FROM users WHERE id = " + id)

	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", id)
	// ruleid: ck-go-sql-built-from-strings
	rows, _ := db.Query(q)
	_ = rows

	// ruleid: ck-go-sql-built-from-strings
	db.ExecContext(ctx, fmt.Sprintf("DELETE FROM users WHERE id = %v", id))

	// ok: ck-go-sql-built-from-strings
	db.Query("SELECT * FROM users WHERE id = $1", id)

	// ok: ck-go-sql-built-from-strings
	db.Query(fmt.Sprintf("SELECT * FROM users LIMIT %d", n))
}

func shellCases(name string) {
	// ruleid: ck-go-shell-command
	exec.Command("sh", "-c", "git log "+name)

	// ruleid: ck-go-shell-command
	exec.CommandContext(ctx, "/bin/bash", "-c", name)

	// ok: ck-go-shell-command
	exec.Command("sh", "-c", "git log --oneline")

	// ok: ck-go-shell-command
	exec.Command("git", "log", name)
}

func netHTTPHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: ck-go-path-from-request
	os.ReadFile(filepath.Join("/srv/files", name))

	// ok: ck-go-path-from-request
	os.ReadFile(filepath.Join("/srv/files", filepath.Base(name)))

	target := r.FormValue("url")
	// ruleid: ck-go-ssrf-from-request
	http.Get(target)

	// ok: ck-go-ssrf-from-request
	http.Get("https://api.example.com/users/" + target)

	next := r.URL.Query().Get("next")
	// ruleid: ck-go-open-redirect
	http.Redirect(w, r, next, http.StatusFound)

	// ok: ck-go-open-redirect
	http.Redirect(w, r, "/home", http.StatusFound)
}

func fiberHandler(c *fiber.Ctx) error {
	tool := c.Query("tool")
	// ruleid: ck-go-command-from-request
	out, _ := exec.Command(tool, "--version").Output()

	// ok: ck-go-command-from-request
	exec.Command("git", "--version")

	// ruleid: ck-go-path-from-request
	return c.SendFile(c.Params("name"))
}

func tlsCases() {
	// ruleid: ck-go-tls-verification-disabled
	_ = &tls.Config{InsecureSkipVerify: true}

	// ok: ck-go-tls-verification-disabled
	_ = &tls.Config{MinVersion: tls.VersionTLS12}
}

func templateCases(userBio string) {
	// ruleid: ck-go-unescaped-template-content
	_ = template.HTML(userBio)

	// ok: ck-go-unescaped-template-content
	_ = template.HTML("<b>static</b>")
}

func hashCases(b []byte) {
	// ruleid: ck-go-weak-hash
	md5.Sum(b)

	// ok: ck-go-weak-hash
	sha256.Sum256(b)
}
