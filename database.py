import sqlite3
from datetime import datetime

class PDUDatabase:
    def __init__(self, db_name='pdcp_pdu.db'):
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS pdus (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            direction TEXT,
            sn INTEGER,
            pdu_type TEXT,
            pdu_data BLOB,
            original_ip_packet BLOB
        )
        ''')
        self.conn.commit()

    def insert_pdu(self, direction, sn, pdu_type, pdu_data, original_ip_packet):
        cursor = self.conn.cursor()
        timestamp = datetime.now().isoformat()
        cursor.execute('''
        INSERT INTO pdus (timestamp, direction, sn, pdu_type, pdu_data, original_ip_packet)
        VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, direction, sn, pdu_type, pdu_data, original_ip_packet))
        self.conn.commit()

    def get_pdu_by_sn(self, sn):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM pdus WHERE sn = ?', (sn,))
        return cursor.fetchone()

    def get_all_pdus(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM pdus')
        return cursor.fetchall()

    def close(self):
        self.conn.close()