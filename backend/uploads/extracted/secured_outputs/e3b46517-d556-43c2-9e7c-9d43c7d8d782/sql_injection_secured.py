import re

def get_user(user_id):
    # Strict allowlist: only digits are permitted
    if not re.fullmatch(r'\d+', str(user_id)):
        raise ValueError('user_id must be a numeric identifier')
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return cursor.fetchone()