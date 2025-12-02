from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from pathlib import Path

APP_NAME = "LP Group Drive"
UPLOAD_FOLDER = Path('/tmp/uploads')
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
DB_PATH = '/tmp/users.db'  # SQLite database in /tmp
MAX_BYTES_PER_USER = 250 * 1024 * 1024
SECRET_KEY = os.environ.get('SECRET_KEY', 'verander_dit_naar_een_random_string')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.secret_key = SECRET_KEY

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'adminLP'


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0,
            is_staff INTEGER DEFAULT 0
        )
    ''')
    
    # Controleer of admin bestaat
    cur.execute('SELECT id FROM users WHERE username = ?', (ADMIN_USERNAME,))
    if not cur.fetchone():
        cur.execute(
            'INSERT INTO users (username, password_hash, active, is_admin, is_staff) VALUES (?, ?, 1, 1, 0)',
            (ADMIN_USERNAME, generate_password_hash(ADMIN_PASSWORD))
        )
    
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user_folder(username):
    folder = UPLOAD_FOLDER / username
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def get_user_usage(username):
    folder = get_user_folder(username)
    return sum(f.stat().st_size for f in folder.iterdir() if f.is_file())


def get_user_files(username):
    folder = get_user_folder(username)
    return sorted(
        [{'name': f.name, 'size': f.stat().st_size} for f in folder.iterdir() if f.is_file()],
        key=lambda x: x['name'].lower()
    )


def is_admin():
    return session.get('is_admin', False)


def is_staff():
    return session.get('is_staff', False)


def is_staff_or_admin():
    return is_admin() or is_staff()


@app.context_processor
def inject_globals():
    return {
        'app_name': APP_NAME,
        'username': session.get('username'),
        'is_admin': is_admin(),
        'is_staff': is_staff()
    }


@app.route('/')
def index():
    if 'username' in session:
        if is_admin():
            return redirect(url_for('admin_panel'))
        if is_staff():
            return redirect(url_for('staff_panel'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# --- LOGIN / LOGOUT ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('Vul alle velden in', 'danger')
            return redirect(url_for('login'))
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username=? AND active=1', (username,))
        user = cur.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            session['user_id'] = user['id']
            session['is_admin'] = bool(user['is_admin'])
            session['is_staff'] = bool(user['is_staff'])
            flash('Succesvol ingelogd', 'success')
            if user['is_admin']:
                return redirect(url_for('admin_panel'))
            if user['is_staff']:
                return redirect(url_for('staff_panel'))
            return redirect(url_for('dashboard'))
        else:
            flash('Ongeldige inloggegevens', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Je bent uitgelogd', 'info')
    return redirect(url_for('login'))


# --- DASHBOARD ---
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    username = session['username']
    files = get_user_files(username)
    used = get_user_usage(username)
    return render_template('dashboard.html', files=files, used=used, limit=MAX_BYTES_PER_USER)


@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    if 'file' not in request.files:
        flash('Geen bestand geselecteerd', 'danger')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('Geen bestand geselecteerd', 'danger')
        return redirect(url_for('dashboard'))
    
    filename = secure_filename(file.filename)
    if not filename:
        flash('Ongeldige bestandsnaam', 'danger')
        return redirect(url_for('dashboard'))
    
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if get_user_usage(username) + file_size > MAX_BYTES_PER_USER:
        flash('Onvoldoende ruimte. Verwijder eerst bestanden.', 'danger')
        return redirect(url_for('dashboard'))
    
    user_folder = get_user_folder(username)
    file.save(str(user_folder / filename))
    flash(f'Bestand "{filename}" geüpload', 'success')
    return redirect(url_for('dashboard'))


@app.route('/download/<filename>')
def download(filename):
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    user_folder = get_user_folder(username)
    safe_filename = secure_filename(filename)
    if not safe_filename:
        abort(404)
    
    file_path = user_folder / safe_filename
    if not file_path.exists() or not file_path.is_file():
        abort(404)
    
    return send_from_directory(str(user_folder), safe_filename, as_attachment=True)


@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    user_folder = get_user_folder(username)
    safe_filename = secure_filename(filename)
    file_path = user_folder / safe_filename
    if file_path.exists() and file_path.is_file():
        file_path.unlink()
        flash(f'Bestand "{safe_filename}" verwijderd', 'success')
    else:
        flash('Bestand niet gevonden', 'danger')
    return redirect(url_for('dashboard'))


# --- INIT ---
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
