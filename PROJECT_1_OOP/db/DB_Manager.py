import mysql.connector
import time

class DatabaseManager():
    def __init__(self,host,user,password,database):
        self.host = host
        self.user = user
        self.password = password
        self.database = database

    def connect(self):
        try:
            
            print("connecting to database...")
            time.sleep(0.5)
            self.Mydb = mysql.connector.connect(
                host = self.host,
                user = self.user,
                password = self.password,
                database = self.database
            )
            self.cursor  = self.Mydb.cursor()
            print("connection successful")
            time.sleep(0.5)
        except mysql.connector.Error as e:
            print(f"some mistakes on {e}")

    def close(self):
        print("terminating the database...")
        time.sleep(0.5)
        if self.cursor:
            self.Mydb.close()
        if self.Mydb:
            self.Mydb.close()
        print("Terminate Successful")
        time.sleep(0.25)
    def delet_data(self):

        self.cursor.execute()



# test conn
# db1 = DatabaseManager("localhost","root","admin","db_network_scanning_system")