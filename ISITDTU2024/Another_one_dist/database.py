import sqlite3

def connect_to_db(db_file):
    try:
        conn = sqlite3.connect(db_file, check_same_thread=False)
        print "Connected to SQLite database successfully"
        return conn
    except sqlite3.Error as e:
        print "Error connecting to database:", e
        return None

def login_db(conn, username, password):
    try:
        cursor = conn.cursor()
        query = "SELECT username, role FROM users WHERE username = ? AND password = ?"
        cursor.execute(query, (username, password))
        return cursor.fetchone()
    except sqlite3.Error as e:
        print "Error executing query:", e
        return None

def register_db(connection, username, password, role):
    try:
        cursor = connection.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return False

        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        connection.commit()
        return True
    except sqlite3.Error as e:
        print "Error during registration:", e
        return False
    finally:
        cursor.close()

def close_connection(conn):
    if conn:
        conn.close()
