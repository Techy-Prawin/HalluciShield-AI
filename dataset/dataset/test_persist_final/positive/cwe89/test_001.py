import sqlite3

def get_user(username):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

if __name__ == '__main__':
    user = get_user('admin')