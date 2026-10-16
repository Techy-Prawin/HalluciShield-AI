import sqlite3
import os

conn = sqlite3.connect(os.path.join(os.getcwd(), 'results.db'))
cursor = conn.cursor()
# List tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()
print('Tables:', tables)
for table in tables:
    cursor.execute(f'PRAGMA table_info({table[0]})')
    print(f'Schema for {table[0]}: {cursor.fetchall()}')
conn.close()