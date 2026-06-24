import os
import sqlite3
import traceback
from datetime import datetime
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, send_from_directory, jsonify, send_file, abort, Response)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project, Document, Comment, Message, AuditLog, DocumentShare

app = Flask(__name__)
app.secret_key = "dummy_flask_secret_key_for_local_testing"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nexusflow.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

db.init_app(app)

# Ensure upload directory exists on import (fixes FileNotFoundError on upload)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# VULN: Weak session configuration — no Secure/HttpOnly hardening, long-lived,
# predictable secret key checked into source (also exposed via /backup/config)
app.config['SESSION_COOKIE_HTTPONLY'] = False   # JS can read session cookie
app.config['SESSION_COOKIE_SAMESITE'] = None    # no CSRF cookie protection
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 30  # 30 days

# VULN: Missing brute-force / rate-limit protection.
# In-memory counter exists for display purposes only — it is NEVER enforced.
login_attempts = {}

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), 'instance', 'nexusflow.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

def log_action(action, resource, details=''):
    try:
        log = AuditLog(
            user_id=session.get('user_id'),
            action=action,
            resource=resource,
            ip_address=request.remote_addr,
            details=details
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass

# ─────────────────────────────────────────────
# Database Init & Seeding
# ─────────────────────────────────────────────

def seed_database():
    if User.query.count() > 0:
        return

    users_data = [
        {
            'username': 'admin',
            'email': 'admin@nexusflow.io',
            'password': generate_password_hash('Admin@123'),
            'full_name': 'Alexandra Chen',
            'role': 'admin',
            'department': 'Engineering',
            'bio': 'Platform administrator and lead engineer.',
            'api_key': 'fake_api_key_for_vulnerable_testing'
        },
        {
            'username': 'marcus.reid',
            'email': 'marcus.reid@nexusflow.io',
            'password': generate_password_hash('Password1!'),
            'full_name': 'Marcus Reid',
            'role': 'member',
            'department': 'Product',
            'bio': 'Senior product manager driving roadmap strategy.',
            'api_key': 'nf_test_api_key_marcus_123456'
        },
        {
            'username': 'priya.sharma',
            'email': 'priya.sharma@nexusflow.io',
            'password': generate_password_hash('Welcome99!'),
            'full_name': 'Priya Sharma',
            'role': 'member',
            'department': 'Design',
            'bio': 'UX designer focused on user-centered design principles.',
            'api_key': 'nf_test_api_key_priya_789012'
        },
        {
            'username': 'daniel.osei',
            'email': 'daniel.osei@nexusflow.io',
            'password': generate_password_hash('Secure#2024'),
            'full_name': 'Daniel Osei',
            'role': 'member',
            'department': 'Marketing',
            'bio': 'Growth marketing lead and content strategist.',
            'api_key': 'nf_test_api_key_daniel_345678'
        },
    ]

    created_users = []
    for u in users_data:
        user = User(**u)
        db.session.add(user)
        created_users.append(user)
    db.session.flush()

    projects_data = [
        {
            'name': 'Q4 Platform Rebrand',
            'description': 'Complete visual and messaging overhaul for the NexusFlow platform ahead of Q4 launch.',
            'status': 'active',
            'owner_id': created_users[0].id,
            'deadline': '2024-12-31',
            'priority': 'high'
        },
        {
            'name': 'API Gateway Migration',
            'description': 'Migrate legacy REST endpoints to GraphQL with backward compatibility layer.',
            'status': 'active',
            'owner_id': created_users[1].id,
            'deadline': '2024-11-15',
            'priority': 'critical'
        },
        {
            'name': 'Enterprise SSO Integration',
            'description': 'SAML 2.0 integration for enterprise customers requiring SSO.',
            'status': 'completed',
            'owner_id': created_users[0].id,
            'deadline': '2024-09-30',
            'priority': 'high'
        },
        {
            'name': 'Mobile App v2.0',
            'description': 'Native iOS and Android application with offline-first architecture.',
            'status': 'active',
            'owner_id': created_users[2].id,
            'deadline': '2025-02-28',
            'priority': 'medium'
        },
    ]

    created_projects = []
    for p in projects_data:
        project = Project(**p)
        db.session.add(project)
        created_projects.append(project)
    db.session.flush()

    docs_data = [
        {
            'title': 'Brand Guidelines 2024',
            'description': 'Official NexusFlow brand standards, color palettes, and typography guide.',
            'filename': 'brand-guidelines-2024.pdf',
            'filepath': 'static/uploads/brand-guidelines-2024.pdf',
            'file_size': 2048576,
            'file_type': 'application/pdf',
            'owner_id': created_users[0].id,
            'project_id': created_projects[0].id,
            'is_private': False,
            'download_count': 47
        },
        {
            'title': 'API Architecture Decision Record',
            'description': 'Technical ADR for the GraphQL migration strategy and implementation plan.',
            'filename': 'api-architecture-adr.docx',
            'filepath': 'static/uploads/api-architecture-adr.docx',
            'file_size': 512000,
            'file_type': 'application/vnd.openxmlformats',
            'owner_id': created_users[1].id,
            'project_id': created_projects[1].id,
            'is_private': False,
            'download_count': 23
        },
        {
            'title': 'SSO Integration Spec (Confidential)',
            'description': 'Internal specification document for SAML configuration and customer secrets.',
            'filename': 'sso-integration-spec.pdf',
            'filepath': 'static/uploads/sso-integration-spec.pdf',
            'file_size': 1024000,
            'file_type': 'application/pdf',
            'owner_id': created_users[0].id,
            'project_id': created_projects[2].id,
            'is_private': True,
            'download_count': 5
        },
        {
            'title': 'Mobile UX Research Report',
            'description': 'User research findings and wireframes for the v2.0 mobile experience.',
            'filename': 'mobile-ux-research.pdf',
            'filepath': 'static/uploads/mobile-ux-research.pdf',
            'file_size': 3145728,
            'file_type': 'application/pdf',
            'owner_id': created_users[2].id,
            'project_id': created_projects[3].id,
            'is_private': False,
            'download_count': 31
        },
        {
            'title': 'Q3 Marketing Performance Deck',
            'description': 'Campaign results, CAC breakdown, and growth metrics for Q3.',
            'filename': 'q3-marketing-performance.pptx',
            'filepath': 'static/uploads/q3-marketing-performance.pptx',
            'file_size': 4194304,
            'file_type': 'application/vnd.ms-powerpoint',
            'owner_id': created_users[3].id,
            'project_id': None,
            'is_private': False,
            'download_count': 12
        },
    ]

    created_docs = []
    for d in docs_data:
        doc = Document(**d)
        db.session.add(doc)
        created_docs.append(doc)
    db.session.flush()

    comments_data = [
        {
            'content': 'The color palette looks great! I think we should also add dark mode variants.',
            'author_id': created_users[2].id,
            'document_id': created_docs[0].id
        },
        {
            'content': 'Agreed on dark mode. Also, the font pairing on page 12 needs revision — the weights conflict at small sizes.',
            'author_id': created_users[1].id,
            'document_id': created_docs[0].id
        },
        {
            'content': 'The GraphQL schema in Appendix A looks solid. Can we get a review from the backend team before sign-off?',
            'author_id': created_users[0].id,
            'document_id': created_docs[1].id
        },
        {
            'content': 'Left detailed comments in the doc. The batching strategy needs re-evaluation for high-concurrency scenarios.',
            'author_id': created_users[1].id,
            'document_id': created_docs[1].id
        },
        {
            'content': 'User testing sessions are scheduled for next week. Will update this report post-synthesis.',
            'author_id': created_users[2].id,
            'document_id': created_docs[3].id
        },
    ]

    for c in comments_data:
        comment = Comment(**c)
        db.session.add(comment)

    msgs_data = [
        {
            'sender_id': created_users[0].id,
            'recipient_id': created_users[1].id,
            'subject': 'API Gateway timeline check-in',
            'body': "Hi Marcus, just checking in on the API gateway migration — are we still on track for the Nov 15 deadline? Let me know if the team needs any additional resources.",
            'is_read': True
        },
        {
            'sender_id': created_users[1].id,
            'recipient_id': created_users[0].id,
            'subject': 'Re: API Gateway timeline check-in',
            'body': "Hi Alexandra, yes we're on track. We've completed about 70% of the endpoint migrations. The remaining ones are the more complex auth flows. Should be done by Nov 10.",
            'is_read': False
        },
        {
            'sender_id': created_users[2].id,
            'recipient_id': created_users[0].id,
            'subject': 'Brand guidelines feedback',
            'body': "The latest version looks really polished. I've added my comments to the document. The main thing I'd flag is the accessibility contrast ratios on the secondary palette.",
            'is_read': False
        },
    ]

    for m in msgs_data:
        msg = Message(**m)
        db.session.add(msg)

    db.session.commit()


# ─────────────────────────────────────────────
# Create a backup config file (vuln: file disclosure)
# ─────────────────────────────────────────────
def create_config_backup():
    backup_path = os.path.join(os.path.dirname(__file__), 'config.bak')
    if not os.path.exists(backup_path):
        with open(backup_path, 'w') as f:
            f.write("""# NexusFlow Configuration Backup
# Generated: 2024-10-01T03:00:00Z
# DO NOT COMMIT TO VERSION CONTROL

[database]
uri = sqlite:///instance/nexusflow.db
backup_uri = postgresql://nexus_prod:Pr0dP@ss#2024@db.internal:5432/nexusflow
backup_schedule = 0 3 * * *

[security]
secret_key = NexusFlow$ecretKey2024!prod
jwt_secret = eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.secret.payload
session_lifetime = 86400

[smtp]
host = smtp.sendgrid.net
port = 587
username = apikey
password = SG.abc123def456ghi789jkl012mno345pqr678stu901vwx234yz

[stripe]
secret_key = dummy_stripe_secret_key
webhook_secret = whsec_abcdefghijklmnopqrstuvwxyz1234567890

[admin]
default_password = Admin@123
recovery_token = rec_9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c

[aws]
access_key_id = AKIAIOSFODNN7EXAMPLE
secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
s3_bucket = nexusflow-prod-uploads
""")

# Generate the backup file on import too (covers `flask run` / WSGI servers)
create_config_backup()

# ─────────────────────────────────────────────
# Public Routes
# ─────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session: 
        return redirect(url_for('dashboard'))
    
    return render_template('index.html', user=current_user())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULN: Missing brute-force protection / rate limiting.
        # Attempts are logged but never block or throttle subsequent requests,
        # and the account is never locked regardless of failure count.
        login_attempts[username] = login_attempts.get(username, 0) + 1

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_attempts[username] = 0
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            log_action('login', 'auth', f'User {username} logged in')
            return redirect(url_for('dashboard'))

        # VULN: Username enumeration — different message reveals whether
        # the username exists in the system.
        if user:
            flash('Incorrect password. Please try again.', 'error')
        else:
            flash(f'No account found for username "{username}".', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        full_name = request.form.get('full_name', '')

        # VULN: Weak password policy — no minimum length, complexity, or
        # common-password check is enforced server-side. A single character
        # like "a" is accepted as a valid password.
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return render_template('register.html')
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            full_name=full_name,
            role='member'
        )
        db.session.add(user)
        db.session.commit()
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        session['role'] = user.role
        return redirect(url_for('dashboard'))
    return render_template('register.html')

# ─────────────────────────────────────────────
# Dashboard
# ─────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    projects = Project.query.order_by(Project.created_at.desc()).limit(5).all()
    documents = Document.query.order_by(Document.created_at.desc()).limit(6).all()
    total_users = User.query.count()
    total_docs = Document.query.count()
    total_projects = Project.query.count()
    unread_msgs = Message.query.filter_by(recipient_id=user.id, is_read=False).count()
    return render_template('dashboard.html', user=user, projects=projects,
                           documents=documents, total_users=total_users,
                           total_docs=total_docs, total_projects=total_projects,
                           unread_msgs=unread_msgs)

# ─────────────────────────────────────────────
# Search — VULN: Reflected XSS
# ─────────────────────────────────────────────

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    results = []
    if query:
        results = Document.query.filter(
            Document.title.ilike(f'%{query}%')
        ).all()
    # Intentionally pass raw query to template for reflection (XSS vuln)
    return render_template('search.html', user=current_user(),
                           query=query, results=results)

# ─────────────────────────────────────────────
# Documents
# ─────────────────────────────────────────────

@app.route('/documents')
@login_required
def documents():
    user = current_user()
    docs = Document.query.order_by(Document.created_at.desc()).all()
    return render_template('documents.html', user=user, documents=docs)

@app.route('/documents/<int:doc_id>')
@login_required
def document_detail(doc_id):
    # VULN: IDOR — no ownership check, any authenticated user can view any doc
    doc = Document.query.get_or_404(doc_id)
    comments = Comment.query.filter_by(document_id=doc_id).all()
    user = current_user()
    return render_template('document_detail.html', user=user, doc=doc, comments=comments)

@app.route('/documents/<int:doc_id>/comment', methods=['POST'])
@login_required
def add_comment(doc_id):
    # VULN: Stored XSS — content stored and rendered without sanitization
    content = request.form.get('content', '')
    user = current_user()
    comment = Comment(
        content=content,
        author_id=user.id,
        document_id=doc_id
    )
    db.session.add(comment)
    db.session.commit()
    log_action('comment_add', 'documents', f'Doc {doc_id}')
    return redirect(url_for('document_detail', doc_id=doc_id))

@app.route('/documents/upload', methods=['GET', 'POST'])
@login_required
def upload_document():
    user = current_user()
    projects = Project.query.all()
    if request.method == 'POST':
        title = request.form.get('title', '')
        description = request.form.get('description', '')
        project_id = request.form.get('project_id') or None
        is_private = bool(request.form.get('is_private'))
        file = request.files.get('file')

        if not file or file.filename == '':
            flash('No file selected.', 'error')
            return render_template('upload.html', user=user, projects=projects)

        # VULN: Unsafe file upload — only checks extension, no MIME validation,
        # allows .php, .py, .sh etc. via double extension or case manipulation
        filename = secure_filename(file.filename)
        allowed_extensions = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
                               'txt', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'csv',
                               'php', 'py', 'sh', 'js', 'html'}  # overly permissive

        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        # Weak check — extension only, easily bypassed
        if ext not in allowed_extensions:
            flash('File type not supported.', 'error')
            return render_template('upload.html', user=user, projects=projects)

        # Ensure the upload directory exists (fixes FileNotFoundError on fresh installs)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Avoid silent overwrite collisions for realism while keeping the
        # vulnerability intact (still no content validation whatsoever)
        if os.path.exists(save_path):
            base, dot, tail = filename.rpartition('.')
            unique_suffix = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
            filename = f'{base}-{unique_suffix}.{tail}' if dot else f'{filename}-{unique_suffix}'
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        file.save(save_path)

        doc = Document(
            title=title,
            description=description,
            filename=filename,
            filepath=f'static/uploads/{filename}',
            file_size=os.path.getsize(save_path),
            file_type=file.content_type,
            owner_id=user.id,
            project_id=project_id,
            is_private=is_private
        )
        db.session.add(doc)
        db.session.commit()
        log_action('document_upload', 'documents', f'Uploaded {filename}')
        flash('Document uploaded successfully.', 'success')
        return redirect(url_for('document_detail', doc_id=doc.id))

    return render_template('upload.html', user=user, projects=projects)

@app.route('/documents/<int:doc_id>/download')
@login_required
def download_document(doc_id):
    # VULN: IDOR — no access control on private documents
    doc = Document.query.get_or_404(doc_id)
    doc.download_count += 1
    db.session.commit()
    upload_dir = app.config['UPLOAD_FOLDER']
    return send_from_directory(upload_dir, doc.filename, as_attachment=True)

@app.route('/documents/<int:doc_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_document(doc_id):
    # VULN: Broken Access Control / IDOR — any authenticated user can edit
    # any document's metadata, not just documents they own. The UI hints at
    # ownership but the server never actually verifies doc.owner_id == user.id.
    doc = Document.query.get_or_404(doc_id)
    user = current_user()
    projects = Project.query.all()

    if request.method == 'POST':
        doc.title = request.form.get('title', doc.title)
        doc.description = request.form.get('description', doc.description)
        project_id = request.form.get('project_id') or None
        doc.project_id = project_id
        doc.is_private = bool(request.form.get('is_private'))
        db.session.commit()
        log_action('document_edit', 'documents', f'Doc {doc_id} edited by user {user.id}')
        flash('Document updated successfully.', 'success')
        return redirect(url_for('document_detail', doc_id=doc.id))

    return render_template('edit_document.html', user=user, doc=doc, projects=projects)

@app.route('/documents/<int:doc_id>/share', methods=['GET', 'POST'])
@login_required
def share_document(doc_id):
    # VULN: Broken Access Control — sharing is allowed by any authenticated
    # user regardless of whether they own the document or have edit rights.
    doc = Document.query.get_or_404(doc_id)
    user = current_user()
    all_users = User.query.filter(User.id != user.id).all()
    existing_shares = DocumentShare.query.filter_by(document_id=doc_id).all()

    if request.method == 'POST':
        recipient_id = request.form.get('user_id')
        permission = request.form.get('permission', 'view')
        if recipient_id:
            share = DocumentShare(
                document_id=doc_id,
                shared_with_id=int(recipient_id),
                shared_by_id=user.id,
                permission=permission
            )
            db.session.add(share)
            db.session.commit()
            log_action('document_share', 'documents', f'Doc {doc_id} shared with user {recipient_id}')
            flash('Document shared successfully.', 'success')
        return redirect(url_for('share_document', doc_id=doc_id))

    return render_template('share_document.html', user=user, doc=doc,
                           all_users=all_users, existing_shares=existing_shares)

@app.route('/documents/<int:doc_id>/share/<int:share_id>/revoke', methods=['POST'])
@login_required
def revoke_share(doc_id, share_id):
    # VULN: Broken Access Control — no check that the requester owns the
    # document or created the original share before revoking it.
    share = DocumentShare.query.get_or_404(share_id)
    db.session.delete(share)
    db.session.commit()
    flash('Access revoked.', 'success')
    return redirect(url_for('share_document', doc_id=doc_id))

@app.route('/shared-with-me')
@login_required
def shared_with_me():
    user = current_user()
    shares = DocumentShare.query.filter_by(shared_with_id=user.id).order_by(DocumentShare.created_at.desc()).all()
    return render_template('shared_with_me.html', user=user, shares=shares)

# ─────────────────────────────────────────────
# VULN: Path Traversal — file download by raw filename
# Looks like a normal "view raw file" convenience link next to the
# IDOR-protected download route above, but takes a user-controlled
# path and joins it onto disk without sanitizing traversal sequences.
# ─────────────────────────────────────────────

@app.route('/download')
@login_required
def download_raw_file():
    """
    Convenience endpoint used by the document viewer's 'Open raw file' link,
    e.g. /download?file=brand-guidelines-2024.pdf
    """
    requested_file = request.args.get('file', '')
    if not requested_file:
        abort(404)

    # VULN: user-controlled filename concatenated directly onto the uploads
    # directory. No normalization / no check that the resolved path stays
    # inside UPLOAD_FOLDER, so '../../' sequences escape the sandbox.
    base_dir = app.config['UPLOAD_FOLDER']
    target_path = os.path.join(base_dir, requested_file)

    if not os.path.isfile(target_path):
        abort(404)

    log_action('file_download', 'download', requested_file)
    return send_file(target_path, as_attachment=True)

# ─────────────────────────────────────────────
# VULN: Local File Inclusion — template preview feature
# A "preview" feature that lets users see a rendered snippet of a
# document template before applying it to a new document. Reads the
# requested template name from disk and reflects its contents.
# ─────────────────────────────────────────────

DOCUMENT_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates_library')

def _ensure_template_library():
    os.makedirs(DOCUMENT_TEMPLATES_DIR, exist_ok=True)
    samples = {
        'project-brief.txt': 'PROJECT BRIEF TEMPLATE\n\nObjective:\nScope:\nStakeholders:\nTimeline:\n',
        'meeting-notes.txt': 'MEETING NOTES TEMPLATE\n\nAttendees:\nAgenda:\nAction Items:\nNext Steps:\n',
        'status-report.txt': 'STATUS REPORT TEMPLATE\n\nSummary:\nProgress:\nBlockers:\nNext Milestones:\n',
    }
    for name, content in samples.items():
        path = os.path.join(DOCUMENT_TEMPLATES_DIR, name)
        if not os.path.exists(path):
            with open(path, 'w') as f:
                f.write(content)

# Ensure the template library exists on import (covers `flask run` / WSGI
# servers that never execute the __main__ block below).
_ensure_template_library()

@app.route('/preview')
@login_required
def preview_template():
    """
    Document creation wizard step: preview a starter template before
    using it, e.g. /preview?template=project-brief.txt
    """
    template_name = request.args.get('template', 'project-brief.txt')

    # VULN: LFI — the template parameter is joined directly onto a base
    # directory and read from disk with no validation that it resolves
    # within DOCUMENT_TEMPLATES_DIR, allowing path traversal to read
    # arbitrary local files (e.g. ../../app.py, ../../config.bak,
    # ../../../../../../etc/passwd).
    template_path = os.path.join(DOCUMENT_TEMPLATES_DIR, template_name)

    try:
        with open(template_path, 'r', errors='replace') as f:
            content = f.read()
        available = sorted(os.listdir(DOCUMENT_TEMPLATES_DIR))
        return render_template('preview_template.html', user=current_user(),
                               template_name=template_name, content=content,
                               available_templates=available)
    except Exception as e:
        # VULN: Verbose error disclosure — full exception detail and
        # absolute server path are returned directly to the client.
        return render_template('preview_template.html', user=current_user(),
                               template_name=template_name, content=None,
                               available_templates=sorted(os.listdir(DOCUMENT_TEMPLATES_DIR)),
                               error=f"Failed to load template '{template_path}': {e}"), 500

# ─────────────────────────────────────────────
# Projects
# ─────────────────────────────────────────────

@app.route('/projects')
@login_required
def projects():
    user = current_user()
    all_projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('projects.html', user=user, projects=all_projects)

@app.route('/projects/new', methods=['GET', 'POST'])
@login_required
def new_project():
    user = current_user()
    if request.method == 'POST':
        name = request.form.get('name', '')
        description = request.form.get('description', '')
        deadline = request.form.get('deadline', '')
        priority = request.form.get('priority', 'medium')
        status = request.form.get('status', 'active')

        if not name:
            flash('Project name is required.', 'error')
            return render_template('new_project.html', user=user)

        project = Project(
            name=name,
            description=description,
            status=status,
            owner_id=user.id,
            deadline=deadline,
            priority=priority
        )
        db.session.add(project)
        db.session.commit()
        log_action('project_create', 'projects', f'Created project {project.id}')
        flash('Project created successfully.', 'success')
        return redirect(url_for('project_detail', project_id=project.id))

    return render_template('new_project.html', user=user)

@app.route('/projects/<int:project_id>')
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    owner = User.query.get(project.owner_id)
    docs = Document.query.filter_by(project_id=project_id).all()
    user = current_user()
    return render_template('project_detail.html', user=user,
                           project=project, owner=owner, docs=docs)

# ─────────────────────────────────────────────
# User Profiles — VULN: IDOR
# ─────────────────────────────────────────────

@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    # VULN: IDOR — any authenticated user can view any profile including private API keys
    target_user = User.query.get_or_404(user_id)
    documents = Document.query.filter_by(owner_id=user_id).all()
    current = current_user()
    return render_template('profile.html', user=current,
                           target_user=target_user, documents=documents)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = current_user()
    if request.method == 'POST':
        user.full_name = request.form.get('full_name', user.full_name)
        user.bio = request.form.get('bio', user.bio)
        user.department = request.form.get('department', user.department)
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('profile', user_id=user.id))
    return render_template('edit_profile.html', user=user)

# ─────────────────────────────────────────────
# Messaging
# ─────────────────────────────────────────────

@app.route('/messages')
@login_required
def messages():
    user = current_user()
    inbox = Message.query.filter_by(recipient_id=user.id).order_by(Message.created_at.desc()).all()
    sent = Message.query.filter_by(sender_id=user.id).order_by(Message.created_at.desc()).all()
    return render_template('messages.html', user=user, inbox=inbox, sent=sent)

@app.route('/messages/<int:msg_id>')
@login_required
def message_detail(msg_id):
    user = current_user()
    # VULN: IDOR — no check that message belongs to current user
    msg = Message.query.get_or_404(msg_id)
    msg.is_read = True
    db.session.commit()
    return render_template('message_detail.html', user=user, msg=msg)

@app.route('/messages/compose', methods=['GET', 'POST'])
@login_required
def compose_message():
    user = current_user()
    users = User.query.filter(User.id != user.id).all()
    if request.method == 'POST':
        recipient_id = request.form.get('recipient_id')
        subject = request.form.get('subject', '')
        body = request.form.get('body', '')
        msg = Message(
            sender_id=user.id,
            recipient_id=int(recipient_id),
            subject=subject,
            body=body
        )
        db.session.add(msg)
        db.session.commit()
        flash('Message sent.', 'success')
        return redirect(url_for('messages'))
    return render_template('compose_message.html', user=user, users=users)

# ─────────────────────────────────────────────
# People Directory
# ─────────────────────────────────────────────

@app.route('/people')
@login_required
def people():
    user = current_user()
    # VULN: SQL Injection — department filter uses raw string interpolation
    dept_filter = request.args.get('department', '')
    conn = get_db_connection()
    if dept_filter:
        query = f"SELECT * FROM users WHERE department = '{dept_filter}' AND is_active = 1"
    else:
        query = "SELECT * FROM users WHERE is_active = 1"
    db_error = None
    try:
        rows = conn.execute(query).fetchall()
    except Exception as e:
        # VULN: Verbose error disclosure — raw SQL, the underlying database
        # driver exception message, and the query string itself are exposed
        # directly to the client, aiding blind/error-based SQLi exploitation.
        rows = []
        db_error = {
            'message': str(e),
            'query': query,
            'type': type(e).__name__
        }
    conn.close()
    departments = db.session.query(User.department).distinct().all()
    departments = [d[0] for d in departments if d[0]]
    return render_template('people.html', user=user, members=rows,
                           departments=departments, dept_filter=dept_filter,
                           db_error=db_error)

# ─────────────────────────────────────────────
# Admin Panel
# ─────────────────────────────────────────────

@app.route('/admin')
@admin_required
def admin_panel():
    user = current_user()
    users = User.query.all()
    total_users = User.query.count()
    total_docs = Document.query.count()
    total_projects = Project.query.count()
    total_messages = Message.query.count()
    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    return render_template('admin.html', user=user, users=users,
                           total_users=total_users, total_docs=total_docs,
                           total_projects=total_projects, total_messages=total_messages,
                           recent_logs=recent_logs)

# VULN: Broken Access Control — this management endpoint checks that the
# user is *logged in* (authentication) but never checks their *role*
# (authorization), unlike /admin which correctly uses @admin_required.
# A regular member can reach the same user list and export it.
@app.route('/admin/users/export')
@login_required
def export_users():
    users = User.query.all()
    lines = ['id,username,email,full_name,role,department,api_key']
    for u in users:
        lines.append(f'{u.id},{u.username},{u.email},{u.full_name},{u.role},{u.department},{u.api_key}')
    csv_content = '\n'.join(lines)
    return Response(csv_content, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=users-export.csv'})

# VULN: Broken Access Control — same pattern, settings page meant for admins
# only checks login state, not role, so any member can view/change
# workspace-wide settings.
@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def workspace_settings():
    user = current_user()
    if request.method == 'POST':
        log_action('settings_change', 'admin', f'Settings updated by user {user.id} (role={user.role})')
        flash('Workspace settings updated.', 'success')
        return redirect(url_for('workspace_settings'))
    return render_template('workspace_settings.html', user=user)

@app.route('/admin/users/<int:user_id>/toggle', methods=['POST'])
@admin_required
def toggle_user(user_id):
    target = User.query.get_or_404(user_id)
    target.is_active = not target.is_active
    db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/users/<int:user_id>/promote', methods=['POST'])
@admin_required
def promote_user(user_id):
    target = User.query.get_or_404(user_id)
    target.role = 'admin' if target.role == 'member' else 'member'
    db.session.commit()
    return redirect(url_for('admin_panel'))

# ─────────────────────────────────────────────
# VULN: Sensitive File Disclosure
# Exposed config backup via predictable route
# ─────────────────────────────────────────────

@app.route('/backup/config')
def config_backup():
    backup_path = os.path.join(os.path.dirname(__file__), 'config.bak')
    if os.path.exists(backup_path):
        return send_file(backup_path, mimetype='text/plain')
    return 'Not found', 404

@app.route('/static/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ─────────────────────────────────────────────
# API Endpoints (simulated internal API)
# ─────────────────────────────────────────────

@app.route('/api/v1/user/me')
@login_required
def api_me():
    user = current_user()
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role,
        'api_key': user.api_key,  # VULN: api key exposed in response
        'department': user.department
    })

@app.route('/api/v1/documents')
@login_required
def api_documents():
    docs = Document.query.all()
    return jsonify([{
        'id': d.id, 'title': d.title, 'owner_id': d.owner_id,
        'is_private': d.is_private, 'created_at': str(d.created_at)
    } for d in docs])

@app.route('/api/v1/users/<int:user_id>')
@login_required
def api_user(user_id):
    # VULN: IDOR via API — returns any user's data including api_key
    u = User.query.get_or_404(user_id)
    return jsonify({
        'id': u.id, 'username': u.username, 'email': u.email,
        'full_name': u.full_name, 'role': u.role, 'department': u.department,
        'api_key': u.api_key, 'bio': u.bio
    })

# ─────────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', user=current_user(),
                           code=403, message="You don't have permission to access this page."), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', user=current_user(),
                           code=404, message="The page you're looking for doesn't exist."), 404

# VULN: Verbose error disclosure — unhandled exceptions return a full
# Python stack trace, internal file paths, and Flask config repr to the
# client instead of a generic error page. This mirrors a debug-mode-left-on
# misconfiguration that's common in real production incidents.
@app.errorhandler(500)
def internal_error(e):
    tb = traceback.format_exc()
    return render_template('error_verbose.html',
                           user=current_user(),
                           error_type=type(e).__name__,
                           error_message=str(e),
                           traceback_text=tb,
                           app_root=os.path.dirname(os.path.abspath(__file__)),
                           db_uri=app.config['SQLALCHEMY_DATABASE_URI']), 500

# ─────────────────────────────────────────────
# App startup
# ─────────────────────────────────────────────

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
        seed_database()
        create_config_backup()
        _ensure_template_library()
    # NOTE: debug=False intentionally — the app ships its own verbose
    # error page (error_verbose.html) as a realistic "prod misconfiguration"
    # information-disclosure vulnerability instead of relying on Flask's
    # interactive debugger (which would allow arbitrary code execution and
    # isn't representative of the kind of bug found in real assessments).
    app.run(debug=False, host='0.0.0.0', port=5004)
