import sqlite3

def insert_user(name):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (name) VALUES ('" + name + "')")
    conn.commit()
    return True

insert_user("alice")