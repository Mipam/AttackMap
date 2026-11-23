"""Corpus fixture (AR048): a deliberately vulnerable Flask app.

Every weakness here is intentional: the labelled expectations in
corpus/reference.yaml pin which registry rules must fire, at which lines.
Keep this file tiny and stable — expectation line ranges depend on it.
"""

import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
DEBUG = True

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_WEBHOOK_SECRET = "whsec_4eC39HqLyjWDarjtT1zdp7dc"


@app.post("/webhooks/stripe")
def stripe_webhook():
    payload = request.get_json()
    conn = sqlite3.connect("/var/data/events.db")
    conn.execute("INSERT INTO events VALUES ('%s')" % payload["type"])  # noqa: UP031 (intentional injection sink)
    return "ok"


@app.get("/admin/users")
def admin_users():
    return []


@app.get("/run")
def run_command():
    cmd = request.args.get("cmd")
    return subprocess.check_output(cmd, shell=True)


@app.get("/greet")
def greet():
    name = request.args.get("name")
    return "<h1>Hello " + name + "</h1>"


@app.route("/upload", methods=["POST"])
def upload():
    from werkzeug.utils import secure_filename

    f = request.files["file"]
    f.save("/srv/uploads/" + secure_filename(f.filename))
    return "saved"


@app.post("/login")
def login():
    token = os.environ["STRIPE_SECRET_KEY"]
    return token


DEFAULT_ADMIN_PASSWORD = "hunter2-123"
