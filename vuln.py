import sqlite3
def get_user(uid):
    db = sqlite3.connect("app.db")
    return db.execute("SELECT * FROM users WHERE id=" + uid).fetchall()
