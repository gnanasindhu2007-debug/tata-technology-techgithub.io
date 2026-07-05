import hashlib
import math
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from model import DeepShieldModel
from report_generator import create_report


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
DB_PATH = BASE_DIR / "deepshield.db"

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("DEEPSHIELD_SECRET_KEY", "deepshield-ai-demo-secret")
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

model = DeepShieldModel()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            filename TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            classification TEXT NOT NULL,
            confidence REAL NOT NULL,
            severity TEXT NOT NULL,
            insights TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        )
        """
    )
    exists = conn.execute("SELECT id FROM users WHERE username = ?", ("engineer",)).fetchone()
    if not exists:
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("engineer", generate_password_hash("deepshield123")),
        )
    conn.commit()
    conn.close()


def login_required():
    return "username" in session


def file_hash(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def entropy(path):
    data = Path(path).read_bytes()
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return -sum((count / len(data)) * math.log2(count / len(data)) for count in counts if count)


@app.before_request
def setup_once():
    init_db()


@app.route("/")
def index():
    if login_required():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session["username"] = username
            flash("Login successful. Welcome to DeepShield AI.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid login. Try engineer / deepshield123.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out safely.", "success")
    return redirect(url_for("thank_you"))


@app.route("/thank-you")
def thank_you():
    return render_template("thank_you.html")


@app.route("/dashboard")
def dashboard():
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans WHERE username = ? ORDER BY id DESC LIMIT 5",
        (session["username"],),
    ).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) AS total FROM scans WHERE username = ?", (session["username"],)
    ).fetchone()["total"]
    conn.close()
    return render_template("dashboard.html", rows=rows, total=total)


@app.route("/scan", methods=["GET", "POST"])
def scan():
    if not login_required():
        return redirect(url_for("login"))
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded or not uploaded.filename:
            flash("Please choose a firmware, executable, package, or diagnostic log file.", "error")
            return redirect(url_for("scan"))

        filename = secure_filename(uploaded.filename)
        saved_path = UPLOAD_DIR / f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
        uploaded.save(saved_path)

        features = {
            "size": saved_path.stat().st_size,
            "entropy": entropy(saved_path),
            "extension": saved_path.suffix.lower(),
            "sha256": file_hash(saved_path),
        }
        result = model.predict(saved_path, features)

        conn = get_db()
        cursor = conn.execute(
            """
            INSERT INTO scans
            (username, filename, file_hash, file_size, classification, confidence, severity, insights, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["username"],
                filename,
                features["sha256"],
                features["size"],
                result["classification"],
                result["confidence"],
                result["severity"],
                result["insights"],
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        conn.commit()
        scan_id = cursor.lastrowid
        conn.close()
        return redirect(url_for("result", scan_id=scan_id))
    return render_template("scan.html")


@app.route("/result/<int:scan_id>")
def result(scan_id):
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND username = ?", (scan_id, session["username"])
    ).fetchone()
    conn.close()
    if not row:
        flash("Scan result was not found.", "error")
        return redirect(url_for("history"))
    return render_template("result.html", row=row)


@app.route("/history")
def history():
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scans WHERE username = ? ORDER BY id DESC", (session["username"],)
    ).fetchall()
    conn.close()
    return render_template("history.html", rows=rows)


@app.route("/report/<int:scan_id>")
def report(scan_id):
    if not login_required():
        return redirect(url_for("login"))
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND username = ?", (scan_id, session["username"])
    ).fetchone()
    conn.close()
    if not row:
        flash("Report could not be created because the scan was not found.", "error")
        return redirect(url_for("history"))
    report_path = create_report(dict(row), REPORT_DIR)
    return send_file(report_path, as_attachment=True)


@app.errorhandler(413)
def file_too_large(_error):
    flash("File is too large. Please upload a file below 32 MB for this demo.", "error")
    return redirect(url_for("scan"))


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="127.0.0.1", port=5000)
