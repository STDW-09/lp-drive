from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from pathlib import Path

APP_NAME = "LP Group Drive"
UPLOAD_FOLDER = Path('uploads')
DB_PATH = 'users.db'
MAX_BYTES_PER_USER = 250 * 1024 * 1024
SECRET_KEY = os.environ.get('SECRET_KEY', 'verander_dit_naar_een_random_string')
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
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
    
    existing_cols = [row[1] for row in cur.execute("PRAGMA table_info(users)").fetchall()]
    if 'is_admin' not in existing_cols:
        cur.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
    if 'is_staff' not in existing_cols:
        cur.execute('ALTER TABLE users ADD COLUMN is_staff INTEGER DEFAULT 0')
    
    cur.execute('SELECT id FROM users WHERE username = ?', (ADMIN_USERNAME,))
    admin_exists = cur.fetchone()
    if not admin_exists:
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
    total = sum(f.stat().st_size for f in folder.iterdir() if f.is_file())
    return total


def get_user_files(username):
    folder = get_user_folder(username)
    files = []
    for f in folder.iterdir():
        if f.is_file():
            files.append({'name': f.name, 'size': f.stat().st_size})
    return sorted(files, key=lambda x: x['name'].lower())


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
        cur.execute('SELECT * FROM users WHERE username = ? AND active = 1', (username,))
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


@app.route('/admin')
def admin_panel():
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id, username, active, is_admin, is_staff FROM users ORDER BY username')
    users = cur.fetchall()
    conn.close()
    
    return render_template('admin.html', users=users)


@app.route('/staff')
def staff_panel():
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_staff_or_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT id, username, active, is_admin, is_staff FROM users WHERE is_admin = 0 AND is_staff = 0 ORDER BY username')
    users = cur.fetchall()
    conn.close()
    
    return render_template('staff.html', users=users)


@app.route('/admin/create_user', methods=['POST'])
def admin_create_user():
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    new_username = request.form.get('new_username', '').strip()
    new_password = request.form.get('new_password', '')
    user_role = request.form.get('user_role', 'user')
    
    if not new_username or not new_password:
        flash('Vul zowel gebruikersnaam als wachtwoord in', 'danger')
        return redirect(url_for('admin_panel'))
    
    if len(new_username) < 3:
        flash('Gebruikersnaam moet minimaal 3 tekens zijn', 'danger')
        return redirect(url_for('admin_panel'))
    
    if len(new_password) < 4:
        flash('Wachtwoord moet minimaal 4 tekens zijn', 'danger')
        return redirect(url_for('admin_panel'))
    
    is_new_staff = 1 if user_role == 'staff' else 0
    is_new_admin = 1 if user_role == 'admin' else 0
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute(
            'INSERT INTO users (username, password_hash, active, is_admin, is_staff) VALUES (?, ?, 1, ?, ?)',
            (new_username, generate_password_hash(new_password), is_new_admin, is_new_staff)
        )
        conn.commit()
        role_text = 'Admin' if is_new_admin else ('Staff' if is_new_staff else 'Gebruiker')
        flash(f'{role_text} "{new_username}" is aangemaakt', 'success')
    except sqlite3.IntegrityError:
        flash(f'Gebruikersnaam "{new_username}" bestaat al', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_panel'))


@app.route('/staff/create_user', methods=['POST'])
def staff_create_user():
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_staff_or_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    new_username = request.form.get('new_username', '').strip()
    new_password = request.form.get('new_password', '')
    
    if not new_username or not new_password:
        flash('Vul zowel gebruikersnaam als wachtwoord in', 'danger')
        return redirect(url_for('staff_panel'))
    
    if len(new_username) < 3:
        flash('Gebruikersnaam moet minimaal 3 tekens zijn', 'danger')
        return redirect(url_for('staff_panel'))
    
    if len(new_password) < 4:
        flash('Wachtwoord moet minimaal 4 tekens zijn', 'danger')
        return redirect(url_for('staff_panel'))
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        cur.execute(
            'INSERT INTO users (username, password_hash, active, is_admin, is_staff) VALUES (?, ?, 1, 0, 0)',
            (new_username, generate_password_hash(new_password))
        )
        conn.commit()
        flash(f'Gebruiker "{new_username}" is aangemaakt', 'success')
    except sqlite3.IntegrityError:
        flash(f'Gebruikersnaam "{new_username}" bestaat al', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('staff_panel'))


@app.route('/admin/toggle_user/<int:user_id>', methods=['POST'])
def admin_toggle_user(user_id):
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('SELECT username, active, is_admin FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    
    if not user:
        flash('Gebruiker niet gevonden', 'danger')
        conn.close()
        return redirect(url_for('admin_panel'))
    
    if user['is_admin']:
        flash('Je kunt de admin-gebruiker niet deactiveren', 'danger')
        conn.close()
        return redirect(url_for('admin_panel'))
    
    new_status = 0 if user['active'] else 1
    cur.execute('UPDATE users SET active = ? WHERE id = ?', (new_status, user_id))
    conn.commit()
    conn.close()
    
    status_text = 'geactiveerd' if new_status else 'gedeactiveerd'
    flash(f'Gebruiker "{user["username"]}" is {status_text}', 'success')
    
    return redirect(url_for('admin_panel'))


@app.route('/staff/toggle_user/<int:user_id>', methods=['POST'])
def staff_toggle_user(user_id):
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_staff_or_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('SELECT username, active, is_admin, is_staff FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    
    if not user:
        flash('Gebruiker niet gevonden', 'danger')
        conn.close()
        return redirect(url_for('staff_panel'))
    
    if user['is_admin'] or user['is_staff']:
        flash('Je kunt geen admin of staff gebruikers wijzigen', 'danger')
        conn.close()
        return redirect(url_for('staff_panel'))
    
    new_status = 0 if user['active'] else 1
    cur.execute('UPDATE users SET active = ? WHERE id = ?', (new_status, user_id))
    conn.commit()
    conn.close()
    
    status_text = 'geactiveerd' if new_status else 'gedeactiveerd'
    flash(f'Gebruiker "{user["username"]}" is {status_text}', 'success')
    
    return redirect(url_for('staff_panel'))


@app.route('/admin/reset_password/<int:user_id>', methods=['GET', 'POST'])
def admin_reset_password(user_id):
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('SELECT id, username, is_admin, is_staff FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    
    if not user:
        flash('Gebruiker niet gevonden', 'danger')
        conn.close()
        return redirect(url_for('admin_panel'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not new_password:
            flash('Vul een nieuw wachtwoord in', 'danger')
            conn.close()
            return render_template('reset_password.html', target_user=user, back_url=url_for('admin_panel'))
        
        if len(new_password) < 4:
            flash('Wachtwoord moet minimaal 4 tekens zijn', 'danger')
            conn.close()
            return render_template('reset_password.html', target_user=user, back_url=url_for('admin_panel'))
        
        if new_password != confirm_password:
            flash('Wachtwoorden komen niet overeen', 'danger')
            conn.close()
            return render_template('reset_password.html', target_user=user, back_url=url_for('admin_panel'))
        
        cur.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                   (generate_password_hash(new_password), user_id))
        conn.commit()
        conn.close()
        
        flash(f'Wachtwoord voor "{user["username"]}" is gewijzigd', 'success')
        return redirect(url_for('admin_panel'))
    
    conn.close()
    return render_template('reset_password.html', target_user=user, back_url=url_for('admin_panel'))


@app.route('/staff/reset_password/<int:user_id>', methods=['GET', 'POST'])
def staff_reset_password(user_id):
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_staff_or_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('SELECT id, username, is_admin, is_staff FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    
    if not user:
        flash('Gebruiker niet gevonden', 'danger')
        conn.close()
        return redirect(url_for('staff_panel'))
    
    if user['is_admin'] or user['is_staff']:
        flash('Je kunt geen wachtwoorden resetten van admin of staff gebruikers', 'danger')
        conn.close()
        return redirect(url_for('staff_panel'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not new_password:
            flash('Vul een nieuw wachtwoord in', 'danger')
            conn.close()
            return render_template('reset_password.html', target_user=user, back_url=url_for('staff_panel'))
        
        if len(new_password) < 4:
            flash('Wachtwoord moet minimaal 4 tekens zijn', 'danger')
            conn.close()
            return render_template('reset_password.html', target_user=user, back_url=url_for('staff_panel'))
        
        if new_password != confirm_password:
            flash('Wachtwoorden komen niet overeen', 'danger')
            conn.close()
            return render_template('reset_password.html', target_user=user, back_url=url_for('staff_panel'))
        
        cur.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                   (generate_password_hash(new_password), user_id))
        conn.commit()
        conn.close()
        
        flash(f'Wachtwoord voor "{user["username"]}" is gewijzigd', 'success')
        return redirect(url_for('staff_panel'))
    
    conn.close()
    return render_template('reset_password.html', target_user=user, back_url=url_for('staff_panel'))


@app.route('/admin/set_role/<int:user_id>', methods=['POST'])
def admin_set_role(user_id):
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    if not is_admin():
        flash('Geen toegang', 'danger')
        return redirect(url_for('dashboard'))
    
    new_role = request.form.get('new_role', 'user')
    
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute('SELECT username, is_admin FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    
    if not user:
        flash('Gebruiker niet gevonden', 'danger')
        conn.close()
        return redirect(url_for('admin_panel'))
    
    if user['is_admin']:
        flash('Je kunt de admin rol niet wijzigen', 'danger')
        conn.close()
        return redirect(url_for('admin_panel'))
    
    is_new_staff = 1 if new_role == 'staff' else 0
    cur.execute('UPDATE users SET is_staff = ? WHERE id = ?', (is_new_staff, user_id))
    conn.commit()
    conn.close()
    
    role_text = 'Staff' if is_new_staff else 'Gebruiker'
    flash(f'"{user["username"]}" is nu {role_text}', 'success')
    
    return redirect(url_for('admin_panel'))


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash('Log eerst in', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    files = get_user_files(username)
    used = get_user_usage(username)
    
    return render_template('dashboard.html', 
                         files=files, 
                         used=used, 
                         limit=MAX_BYTES_PER_USER)


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
    
    current_usage = get_user_usage(username)
    if current_usage + file_size > MAX_BYTES_PER_USER:
        flash('Onvoldoende ruimte. Verwijder eerst bestanden.', 'danger')
        return redirect(url_for('dashboard'))
    
    user_folder = get_user_folder(username)
    file_path = user_folder / filename
    file.save(str(file_path))
    
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
    if not safe_filename:
        flash('Ongeldige bestandsnaam', 'danger')
        return redirect(url_for('dashboard'))
    
    file_path = user_folder / safe_filename
    if file_path.exists() and file_path.is_file():
        file_path.unlink()
        flash(f'Bestand "{safe_filename}" verwijderd', 'success')
    else:
        flash('Bestand niet gevonden', 'danger')
    
    return redirect(url_for('dashboard'))


init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
