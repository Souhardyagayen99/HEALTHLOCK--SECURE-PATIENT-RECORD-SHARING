import os
import datetime
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv

from crypto_utils import load_or_create_fernet, encrypt_text, decrypt_text

# Load environment variables from .env if present
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///healthlock.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Database
db = SQLAlchemy(app)

# Fernet
fernet = load_or_create_fernet(os.getenv('FERNET_KEY_PATH', 'fernet.key'))


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class PatientRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(200), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    created_by = db.relationship('User', backref=db.backref('records', lazy=True))


# DB initialization and default admin user
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()


# Auth helpers

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)


# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('list_records'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash('Logged in successfully.', 'success')
            return redirect(url_for('list_records'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/records')
@login_required
def list_records():
    records = PatientRecord.query.order_by(PatientRecord.created_at.desc()).all()
    return render_template('records_list.html', records=records, current_user=get_current_user())


@app.route('/records/new', methods=['GET', 'POST'])
@login_required
def create_record():
    if request.method == 'POST':
        patient_name = request.form.get('patient_name', '').strip()
        content = request.form.get('content', '')
        if not patient_name or not content:
            flash('Patient name and content are required.', 'warning')
            return render_template('record_new.html')
        encrypted = encrypt_text(fernet, content)
        record = PatientRecord(
            patient_name=patient_name,
            encrypted_content=encrypted,
            created_by_user_id=get_current_user().id,
        )
        db.session.add(record)
        db.session.commit()
        flash('Record created.', 'success')
        return redirect(url_for('list_records'))
    return render_template('record_new.html')


@app.route('/records/<int:record_id>')
@login_required
def view_record(record_id: int):
    record = db.session.get(PatientRecord, record_id)
    if not record:
        flash('Record not found.', 'warning')
        return redirect(url_for('list_records'))
    try:
        decrypted = decrypt_text(fernet, record.encrypted_content)
    except Exception:
        decrypted = '[Decryption failed]'
    return render_template('record_view.html', record=record, content=decrypted)


@app.route('/records/<int:record_id>/share', methods=['POST', 'GET'])
@login_required
def share_record(record_id: int):
    record = db.session.get(PatientRecord, record_id)
    if not record:
        flash('Record not found.', 'warning')
        return redirect(url_for('list_records'))

    max_age = int(os.getenv('SHARE_TOKEN_MAX_AGE_SECONDS', '3600'))
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='share-token')

    if request.method == 'POST':
        token = serializer.dumps({'record_id': record.id})
        share_url = url_for('open_share', token=token, _external=True)
        return render_template('share_link.html', share_url=share_url, max_age=max_age)

    return render_template('share_confirm.html', record=record, max_age=max_age)


@app.route('/share/<token>')
def open_share(token: str):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'], salt='share-token')
    max_age = int(os.getenv('SHARE_TOKEN_MAX_AGE_SECONDS', '3600'))
    try:
        data = serializer.loads(token, max_age=max_age)
        record_id = data.get('record_id')
    except SignatureExpired:
        return render_template('share_open.html', error='Link expired.'), 410
    except BadSignature:
        return render_template('share_open.html', error='Invalid link.'), 400

    record = db.session.get(PatientRecord, record_id)
    if not record:
        return render_template('share_open.html', error='Record not found.'), 404
    try:
        decrypted = decrypt_text(fernet, record.encrypted_content)
    except Exception:
        return render_template('share_open.html', error='Failed to decrypt.'), 500

    return render_template('share_open.html', error=None, record=record, content=decrypted)


# Static route to serve the key download notice or robots if needed
@app.route('/robots.txt')
def robots_txt():
    return "User-agent: *\nDisallow: /", 200, {'Content-Type': 'text/plain'}


if __name__ == '__main__':
    port = int(os.getenv('PORT', '5000'))
    app.run(debug=True, host='0.0.0.0', port=port)
