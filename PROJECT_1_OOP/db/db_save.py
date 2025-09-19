import mysql.connector
from mysql.connector import errorcode
from DB_Manager import DatabaseManager
from datetime import datetime
import random

def db_connection():
    db_name = {
                "host" : "localhost",
                "user" : "root",
                "password" : "admin",
                "database" : "db_network_scanning_system"
            }

    connect_db = DatabaseManager(**db_name)
    connect_db.connect()
    cursor = connect_db.Mydb.cursor()
    cursor.execute



    

# mapping port yang bakal jadi parameter db
PORT_SERVICE ={
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    21: "FTP",
    53: "DNS",
}

def save_result(target_ip, port, open_ports):
    MyCursor = db_connection()
    cursor = MyCursor.cursor()

    # insert scans table
    scan_id = f"S{random.randint(1000,9999)}"
    scan_date = datetime.now()


tes = save_result()   