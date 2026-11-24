"""Tiny catalog service fixture for portfolio mode (AR081).

Deliberately minimal: one route, one outbound call to the shared external
host, one sqlite database hint, one shared secret marker.
"""

import os
import sqlite3

import requests
from flask import Flask

app = Flask(__name__)


@app.route("/items")
def list_items():
    conn = sqlite3.connect("catalog.db")
    token = os.getenv("SHARED_SERVICE_TOKEN")
    response = requests.get("https://api.example.com/v1/items", timeout=5)
    return {"count": len(conn.execute("SELECT 1").fetchall()), "token": token,
            "items": response.json()}
