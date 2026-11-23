"""Fixture whose filename uses Cyrillic 'а/р/р' confusables for 'app'."""

from flask import Flask

app = Flask(__name__)


@app.route("/cyrillic")
def cyrillic():
    return "ok"
