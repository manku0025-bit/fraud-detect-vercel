import sqlite3

db=sqlite3.connect("users.db")
cur=db.cursor()

cur.execute("""
CREATE TABLE users(
fullname TEXT,
email TEXT,
mobile TEXT,
password TEXT
)
""")

db.commit()
db.close()

print("Database Created")