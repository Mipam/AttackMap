"""Tiny billing service fixture for portfolio mode (AR081).

Shares the external host and the requests dependency with catalog, the
postgresql database kind and the secret marker with notifier.
"""

import os

import psycopg2
import requests
from fastapi import FastAPI

app = FastAPI()


@app.get("/charges")
def list_charges():
    conn = psycopg2.connect("postgresql://localhost/billing")
    token = os.getenv("SHARED_SERVICE_TOKEN")
    response = requests.post("https://api.example.com/v1/charges", timeout=5)
    return {"charges": response.json(), "conn": conn, "token": token}
