"""Tiny notifier worker fixture for portfolio mode (AR081).

Plain Python (no web framework): shares the secret marker with catalog and
billing, the postgresql kind with billing, and keeps its own external host,
database kind and dependency so the portfolio graph has distinct edges too.
"""

import os

import psycopg2
import redis
import requests


def notify():
    token = os.getenv("SHARED_SERVICE_TOKEN")
    conn = psycopg2.connect("postgresql://localhost/events")
    cache = redis.Redis(host="localhost")
    metrics = requests.get("https://metrics.internal/api", timeout=5)
    cache.set("last", metrics.text)
    return token, conn
