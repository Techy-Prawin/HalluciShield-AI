import sqlite3


def get_user(username):
    """Vulnerable to SQL injection."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def get_user_safe(username):
    """Safe parameterized query."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()


def create_user(username, password):
    """Vulnerable to SQL injection."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
    cursor.execute(query)
    conn.commit()
