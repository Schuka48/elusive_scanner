import psycopg2
import os


class IPDatabase:
    def __init__(self):
        self.conn = psycopg2.connect(
            dbname='postgres',
            user=os.environ.get('PG_USER'),
            # user='postgres',
            password=os.environ.get('PG_USER'),
            # password='postgres',
            host='localhost',
            port=5432
        )
        self.cur = self.conn.cursor()

    def create_table(self):
        self.cur.execute('''
            CREATE TABLE IF NOT EXISTS ips (
                id SERIAL PRIMARY KEY,
                address INET NOT NULL
            );
        ''')
        self.conn.commit()

    def insert_ip_address(self, ip_address: str):
        self.cur.execute("INSERT INTO ips (address) VALUES (%s)", (ip_address,))
        self.conn.commit()

    def delete_ip_address(self, ip_address: str):
        self.cur.execute("DELETE FROM ips where address = (%s)", (ip_address,))
        self.conn.commit()

    def get_ips(self):
        self.cur.execute("SELECT address FROM ips;")
        return self.cur.fetchall()

    def __del__(self):
        self.cur.close()
        self.conn.close()


if __name__ == '__main__':
    db_conn = IPDatabase()
    # db_conn.delete_ip_address('192.168.25.1')
    print(db_conn.get_ips())
