import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, redirect, request, send_file

app = Flask(__name__)


def sql_cases(cursor, uid):
    # ruleid: ck-python-sql-built-from-strings
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")

    query = "SELECT * FROM users WHERE name = '%s'" % uid
    # ruleid: ck-python-sql-built-from-strings
    cursor.execute(query)

    # ruleid: ck-python-sql-built-from-strings
    cursor.execute("DELETE FROM users WHERE id = {}".format(uid))

    # ok: ck-python-sql-built-from-strings
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))


def shell_cases(name):
    # ruleid: ck-python-shell-command
    subprocess.run("git log " + name, shell=True)

    # ruleid: ck-python-shell-command
    os.system(f"rm -rf {name}")

    # ok: ck-python-shell-command
    subprocess.run("git log --oneline", shell=True)

    # ok: ck-python-shell-command
    subprocess.run(["git", "log", name])


@app.route("/run")
def run_tool():
    tool = request.args.get("tool")
    # ruleid: ck-python-command-from-request
    subprocess.run([tool, "--version"])
    # ok: ck-python-command-from-request
    subprocess.run(["git", "--version"])
    return "ok"


@app.route("/download")
def download():
    name = request.args.get("name")
    # ruleid: ck-python-path-from-request
    return send_file(os.path.join("/srv/files", name))


@app.route("/download-safe")
def download_safe():
    name = request.args.get("name")
    # ok: ck-python-path-from-request
    return send_file(os.path.join("/srv/files", os.path.basename(name)))


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: ck-python-ssrf-from-request
    requests.get(url)
    # ok: ck-python-ssrf-from-request
    requests.get(f"https://api.example.com/users/{url}")
    return "ok"


@app.route("/login")
def login():
    nxt = request.args.get("next")
    # ruleid: ck-python-open-redirect
    return redirect(nxt)


@app.route("/home")
def home():
    # ok: ck-python-open-redirect
    return redirect("/dashboard")


def eval_cases(expr):
    # ruleid: ck-python-eval
    eval(expr)
    # ok: ck-python-eval
    eval("1 + 1")


def deserialization_cases(blob, stream):
    # ruleid: ck-python-unsafe-deserialization
    pickle.loads(blob)
    # ruleid: ck-python-unsafe-deserialization
    yaml.load(stream, Loader=yaml.Loader)
    # ok: ck-python-unsafe-deserialization
    yaml.load(stream, Loader=yaml.SafeLoader)
    # ok: ck-python-unsafe-deserialization
    yaml.safe_load(stream)


def tls_cases(url):
    # ruleid: ck-python-tls-verification-disabled
    requests.get(url, verify=False)
    # ok: ck-python-tls-verification-disabled
    requests.get(url, verify="/etc/ssl/ca.pem")


def hash_cases(data):
    # ruleid: ck-python-weak-hash
    hashlib.md5(data)
    # ok: ck-python-weak-hash
    hashlib.md5(data, usedforsecurity=False)
    # ok: ck-python-weak-hash
    hashlib.sha256(data)


if __name__ == "__main__":
    # ruleid: ck-python-flask-debug
    app.run(debug=True)
