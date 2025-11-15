"""MySQL users table + salted hashing (no chat storage).""" 
import os
import pymysql
import argparse
from dotenv import load_dotenv

load_dotenv()

def get_conn():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME"),
        autocommit=True,
    )

def init_db():
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        username VARCHAR(255) UNIQUE NOT NULL,
        salt VARBINARY(16) NOT NULL,
        pwd_hash CHAR(64) NOT NULL
    );
    """

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(schema)

    print("Database initialized successfully.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true")
    args = parser.parse_args()

    if args.init:
        init_db()

