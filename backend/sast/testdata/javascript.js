const child_process = require("child_process");
const { exec } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const express = require("express");

const app = express();

async function sqlCases(db, id) {
  // ruleid: ck-js-sql-built-from-strings
  await db.query(`SELECT * FROM users WHERE id = ${id}`);

  const q = "SELECT * FROM users WHERE name = '" + id + "'";
  // ruleid: ck-js-sql-built-from-strings
  await db.query(q);

  // ok: ck-js-sql-built-from-strings
  await db.query("SELECT * FROM users WHERE id = $1", [id]);

  // ok: ck-js-sql-built-from-strings
  await db.query(`SELECT * FROM users`);
}

function shellCases(name) {
  // ruleid: ck-js-shell-command
  exec(`git log ${name}`);

  // ruleid: ck-js-shell-command
  child_process.execSync("git log " + name);

  // ok: ck-js-shell-command
  exec("git log --oneline");

  // ok: ck-js-shell-command
  /a(b)/.exec(name);
}

app.get("/run", (req, res) => {
  const tool = req.query.tool;
  // ruleid: ck-js-command-from-request
  child_process.spawn(tool, ["--version"]);
  // ok: ck-js-command-from-request
  child_process.spawn("git", ["--version"]);
  res.send("ok");
});

app.get("/download", (req, res) => {
  // ruleid: ck-js-path-from-request
  fs.readFile(path.join("/srv/files", req.query.name), () => {});
  // ok: ck-js-path-from-request
  fs.readFile(path.join("/srv/files", path.basename(req.query.name)), () => {});
  // ok: ck-js-path-from-request
  res.sendFile(req.params.name, { root: "/srv/files" });
});

app.get("/fetch", async (req, res) => {
  const url = req.query.url;
  // ruleid: ck-js-ssrf-from-request
  await fetch(url);
  // ruleid: ck-js-ssrf-from-request
  await axios.get(url);
  // ok: ck-js-ssrf-from-request
  await fetch(`https://api.example.com/users/${url}`);
  res.send("ok");
});

app.get("/login", (req, res) => {
  // ruleid: ck-js-open-redirect
  res.redirect(req.query.next);
});

app.get("/home", (req, res) => {
  // ok: ck-js-open-redirect
  res.redirect("/dashboard");
});

function htmlCases(el, bio) {
  // ruleid: ck-js-html-injection
  el.innerHTML = bio;
  // ok: ck-js-html-injection
  el.innerHTML = "";
  // ok: ck-js-html-injection
  el.innerHTML = DOMPurify.sanitize(bio);
}

function evalCases(expr) {
  // ruleid: ck-js-eval
  eval(expr);
  // ok: ck-js-eval
  eval("1 + 1");
}

function tlsCases() {
  // ruleid: ck-js-tls-verification-disabled
  const agent = { rejectUnauthorized: false };
  // ok: ck-js-tls-verification-disabled
  const strict = { rejectUnauthorized: true };
}

function hashCases(data) {
  // ruleid: ck-js-weak-hash
  crypto.createHash("md5").update(data);
  // ok: ck-js-weak-hash
  crypto.createHash("sha256").update(data);
}
