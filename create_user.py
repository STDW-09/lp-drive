# Script om gebruikers aan te maken via shell
import sys
import sqlite3
from werkzeug.security import generate_password_hash
DB_PATH = 'users.db'
if len(sys.argv) != 3:
    print('Gebruik: python create_user.py gebruikersnaam wachtwoord')
    sys.exit(1)
username = sys.argv[1].strip()
password = sys.argv[2]
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
try:
    cur.execute('INSERT INTO users (username, password_hash, active) VALUES (?, ?, 1)',
                (username, generate_password_hash(password)))
    conn.commit()
    print(f'Gebruiker {username} aangemaakt')
except Exception as e:
    print('Fout:', e)
finally:
    conn.close()