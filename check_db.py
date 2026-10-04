import sqlite3

def check_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    if not tables:
        print("Database has no tables.")
    else:
        for name, sql in tables:
            print(f"Table: {name}\nSchema: {sql}\n")
    
    # Also fetch sample data from logs if it exists
    try:
        cursor.execute("SELECT * FROM logs LIMIT 5")
        print("Sample data from 'logs':", cursor.fetchall())
    except sqlite3.OperationalError:
        pass

if __name__ == '__main__':
    check_db()
