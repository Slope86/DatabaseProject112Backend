import os

import mysql.connector
from dotenv import load_dotenv


class Database:
    def __init__(self, database_name: str | None = None):
        load_dotenv(override=True)
        if database_name is None:
            database_name = os.getenv("DB_NAME")
        self.db_config = {
            "host": os.getenv("DB_HOST"),
            "user": os.getenv("DB_USER"),
            "password": os.getenv("DB_PASS"),
            "port": os.getenv("DB_PORT"),
            "database": database_name,
        }
        self.conn = mysql.connector.connect(**self.db_config)
        self.cursor = self.conn.cursor()

    def __del__(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()


if __name__ == "__main__":
    db = Database()
    print(db.db_config)
    print(db.conn)
    print(db.cursor)
