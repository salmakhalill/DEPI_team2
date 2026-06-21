"""
=====================================================================
 INTENTIONALLY VULNERABLE FLASK APPLICATION
 FOR EDUCATIONAL / SECURITY-TRAINING USE ONLY.
 DO NOT deploy this on a public server or use any of this code
 as a reference for real-world application design.
=====================================================================

Tech stack (strict, no extra deps beyond Flask itself):
  - Flask
  - sqlite3 (Python standard library, no ORM)
  - Jinja2 templates (ships with Flask)
  - Plain HTML/CSS

Run with:
    python app.py

The app will auto-create and seed database.db and the uploads/
folder (including a couple of "sensitive" files) on first run.
"""

import os
import sqlite3
from datetime import datetime

from flask import (
    Flask, request, render_template, redirect, url_for,
    session, flash, Response, send_file, abort
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

app = Flask(__name__)

# VULNERABILITY (bonus): hardcoded, weak secret key.
# Anyone who reads the source (or guesses it) can forge session cookies.
app.secret_key = "supersecretkey123"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables and seed demo data if the DB doesn't exist yet."""
    first_run = not os.path.exists(DB_PATH)
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            bio TEXT,
            is_admin INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            content TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            filename TEXT,
            original_name TEXT,
            uploaded_at TEXT
        );
        """
    )
    conn.commit()

    if first_run:
        # NOTE: passwords are stored in PLAINTEXT on purpose (additional
        # weakness used to make the SQLi / IDOR demos more impactful).
        conn.execute(
            "INSERT INTO users (username, password, email, bio, is_admin) "
            "VALUES (?,?,?,?,?)",
            ("admin", "admin123", "admin@vulnerable.local",
             "System administrator. See /uploads for internal notes.", 1),
        )
        conn.execute(
            "INSERT INTO users (username, password, email, bio, is_admin) "
            "VALUES (?,?,?,?,?)",
            ("alice", "alice123", "alice@example.com",
             "Hi, I'm Alice. I love hiking and houseplants.", 0),
        )
        conn.execute(
            "INSERT INTO users (username, password, email, bio, is_admin) "
            "VALUES (?,?,?,?,?)",
            ("bob", "bob123", "bob@example.com",
             "Bob here. Currently learning Flask.", 0),
        )
        conn.execute(
            "INSERT INTO comments (user_id, username, content, created_at) "
            "VALUES (?,?,?,?)",
            (2, "alice", "Welcome to the site, excited to be here!",
             datetime.now().isoformat()),
        )
        conn.execute(
            "INSERT INTO comments (user_id, username, content, created_at) "
            "VALUES (?,?,?,?)",
            (3, "bob", "Anyone know a good plugin for this site?",
             datetime.now().isoformat()),
        )
        conn.commit()
    conn.close()


def seed_uploads():
    """Drop a couple of 'sensitive' files into uploads/ to demonstrate
    sensitive file disclosure via predictable / discoverable filenames."""
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    notes_path = os.path.join(UPLOAD_FOLDER, "admin_notes.txt")
    if not os.path.exists(notes_path):
        with open(notes_path, "w") as f:
            f.write(
                "INTERNAL NOTES - DO NOT SHARE\n"
                "------------------------------\n"
                "TODO: rotate the demo admin password (currently admin123)\n"
                "TODO: disable the legacy /download endpoint before launch\n"
                "Backup credentials file: backup_credentials.txt\n"
            )

    backup_path = os.path.join(UPLOAD_FOLDER, "backup_credentials.txt")
    if not os.path.exists(backup_path):
        with open(backup_path, "w") as f:
            f.write(
                "# demo credential backup (FAKE DATA, for training only)\n"
                "admin:admin123\n"
                "alice:alice123\n"
                "bob:bob123\n"
            )


# ---------------------------------------------------------------------------
# Routes: Home
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    conn = get_db()
    recent_comments = conn.execute(
        "SELECT * FROM comments ORDER BY id DESC LIMIT 5"
    ).fetchall()
    conn.close()
    return render_template("home.html", comments=recent_comments)


# ---------------------------------------------------------------------------
# Routes: Register / Login / Logout
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        bio = request.form.get("bio", "")

        conn = get_db()
        try:
            # Parameterized here -- registration itself is not the target
            # vulnerability, login/search are (see vulnerability_map.md).
            conn.execute(
                "INSERT INTO users (username, password, email, bio, is_admin) "
                "VALUES (?,?,?,?,0)",
                (username, password, email, bio),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("That username is already taken.")
            conn.close()
            return redirect(url_for("register"))
        conn.close()
        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = get_db()

        # ------------------------------------------------------------
        # VULNERABILITY #3: SQL INJECTION
        # Raw string formatting straight into the query -> classic
        # authentication-bypass / UNION-based SQLi.
        # Example bypass username field:  admin' OR '1'='1
        # ------------------------------------------------------------
        query = (
            "SELECT * FROM users WHERE username = '"
            + username
            + "' AND password = '"
            + password
            + "'"
        )
        try:
            user = conn.execute(query).fetchone()
        except sqlite3.Error as e:
            # VULNERABILITY (bonus): raw DB error leaked to the user,
            # which helps an attacker fingerprint the query/schema.
            flash("Database error: " + str(e))
            conn.close()
            return redirect(url_for("login"))

        conn.close()

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = user["is_admin"]
            flash("Logged in as " + user["username"])
            return redirect(url_for("profile", user_id=user["id"]))
        else:
            flash("Invalid credentials.")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# Routes: Profile (IDOR)
# ---------------------------------------------------------------------------

@app.route("/profile/<int:user_id>")
def profile(user_id):
    if "user_id" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    conn = get_db()

    # ------------------------------------------------------------
    # VULNERABILITY #4: IDOR (Insecure Direct Object Reference)
    # There is no check that session['user_id'] == user_id. Any
    # logged-in user can view ANY other user's profile -- including
    # email, bio and (since passwords are stored in plaintext for
    # this demo) their password -- just by changing the URL.
    # ------------------------------------------------------------
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()

    if not user:
        conn.close()
        abort(404)

    user_files = conn.execute(
        "SELECT * FROM files WHERE user_id = ?", (user_id,)
    ).fetchall()
    conn.close()

    is_own = session["user_id"] == user_id
    return render_template(
        "profile.html", user=user, files=user_files, is_own=is_own
    )


# ---------------------------------------------------------------------------
# Routes: Search (Reflected XSS + SQL Injection)
# ---------------------------------------------------------------------------

@app.route("/search")
def search():
    query = request.args.get("q", "")
    results = []
    error = None

    if query:
        conn = get_db()
        # ------------------------------------------------------------
        # VULNERABILITY #3 (again): SQL INJECTION via string concat.
        # Try: %' UNION SELECT id, username, password, email FROM users--
        # ------------------------------------------------------------
        sql = (
            "SELECT id, username, email, bio FROM users "
            "WHERE username LIKE '%" + query + "%'"
        )
        try:
            results = conn.execute(sql).fetchall()
        except sqlite3.Error as e:
            error = str(e)
        conn.close()

    # ------------------------------------------------------------
    # VULNERABILITY #1: REFLECTED XSS
    # `query` is echoed back into the page and rendered with the
    # |safe filter in search.html, so <script> payloads in ?q=
    # execute in the victim's browser.
    # Try: /search?q=<script>alert(document.cookie)</script>
    # ------------------------------------------------------------
    return render_template(
        "search.html", query=query, results=results, error=error
    )


# ---------------------------------------------------------------------------
# Routes: Comments (Stored XSS)
# ---------------------------------------------------------------------------

@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        if "user_id" not in session:
            flash("Please log in to comment.")
            return redirect(url_for("login"))

        content = request.form.get("content", "")
        conn = get_db()
        # Content is stored completely as-is, no sanitization/escaping.
        conn.execute(
            "INSERT INTO comments (user_id, username, content, created_at) "
            "VALUES (?,?,?,?)",
            (session["user_id"], session["username"], content,
             datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()
        return redirect(url_for("comments"))

    conn = get_db()
    all_comments = conn.execute(
        "SELECT * FROM comments ORDER BY id DESC"
    ).fetchall()
    conn.close()

    # ------------------------------------------------------------
    # VULNERABILITY #2: STORED XSS
    # comments.html renders {{ comment.content|safe }}, so any HTML/JS
    # a user submits here gets executed in every future visitor's browser.
    # Try posting: <script>alert('stored-xss')</script>
    # ------------------------------------------------------------
    return render_template("comments.html", comments=all_comments)


# ---------------------------------------------------------------------------
# Routes: File upload (Unsafe upload)
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        flash("Please log in to upload files.")
        return redirect(url_for("login"))

    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            # ------------------------------------------------------------
            # VULNERABILITY #6: UNSAFE FILE UPLOAD
            # - No extension/MIME-type allow-list at all (any file type,
            #   including .html/.svg/.php/etc, can be uploaded).
            # - The ORIGINAL filename is used unsanitized (no
            #   secure_filename()), so it can contain path-traversal
            #   sequences like ../../app.py to write/overwrite files
            #   outside the uploads folder.
            # - No file-size limit.
            # ------------------------------------------------------------
            filename = f.filename
            dest_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            f.save(dest_path)

            conn = get_db()
            conn.execute(
                "INSERT INTO files (user_id, username, filename, "
                "original_name, uploaded_at) VALUES (?,?,?,?,?)",
                (session["user_id"], session["username"], filename,
                 f.filename, datetime.now().isoformat()),
            )
            conn.commit()
            conn.close()
            flash("File uploaded: " + filename)
        else:
            flash("No file selected.")
        return redirect(url_for("upload"))

    conn = get_db()
    # VULNERABILITY #4 (again, IDOR-style): every uploaded file from every
    # user is listed here, not just the current user's own files.
    all_files = conn.execute(
        "SELECT * FROM files ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("upload.html", files=all_files)


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    """Serve an uploaded file by name.

    VULNERABILITY #6 (continued): because uploads are not restricted by
    type, an attacker can upload an .html file containing <script> and
    then have it served back with a text/html content-type here, turning
    'file upload' into a second, more persistent flavor of stored XSS.
    """
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.isfile(filepath):
        abort(404)
    return send_file(filepath)


@app.route("/download/<path:filename>")
def download(filename):
    """A 'legacy' raw file-download endpoint.

    VULNERABILITY #5: SENSITIVE FILE DISCLOSURE / PATH TRAVERSAL
    The filename from the URL is joined onto the uploads directory with
    NO normalization or sanitization, and no check that the resulting
    path stays inside uploads/. A '../' sequence escapes the uploads
    folder entirely, allowing arbitrary file read of anything the
    server process can access (app.py, database.db, /etc/passwd, etc).
    Try: /download/../app.py   or   /download/../database.db
    """
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    try:
        with open(filepath, "rb") as fh:
            data = fh.read()
    except (FileNotFoundError, IsADirectoryError):
        abort(404)
    return Response(data, mimetype="application/octet-stream")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    seed_uploads()
    print("=" * 70)
    print(" Intentionally Vulnerable Flask App")
    print(" Demo accounts: admin/admin123, alice/alice123, bob/bob123")
    print(" Running at http://127.0.0.1:5000")
    print(" FOR EDUCATIONAL / SECURITY-TRAINING USE ONLY.")
    print("=" * 70)
    app.run(debug=True, host="127.0.0.1", port=5000)