import sqlite3
import os

def initialize_database(db_path="data/manageapp.db"):
    #if not os.path.exists(os.path.dirname(db_path)):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = sqlite3.connect(db_path)
    c = db.cursor()

    # TO create the table acccount
    c.execute("""CREATE TABLE IF NOT EXISTS "account" (
    "id"          INTEGER PRIMARY KEY AUTOINCREMENT,
    "username"    TEXT NOT NULL UNIQUE,
    "password"    TEXT NOT NULL,
    "email"       TEXT,
    "admin"       TEXT NOT NULL,
    "creationdate" NUMERIC NOT NULL
);""")
    
    # this creates table for infoapplication
    # Moved up because userapplication references it
    c.execute("""CREATE TABLE IF NOT EXISTS "infoapplication" (
          "nameapp"   TEXT,
          PRIMARY KEY("nameapp")
          );""")

    # THis creates table for event
    c.execute("""CREATE TABLE IF NOT EXISTS "event" (
          "logindate"   NUMERIC NOT NULL,
          "event"   TEXT,
          "username"   TEXT NOT NULL,
          CONSTRAINT "usepk" FOREIGN KEY("username") REFERENCES "account"("username")
          ON DELETE CASCADE ON UPDATE CASCADE
          );""")

# This creates table for user application
    c.execute("""CREATE TABLE IF NOT EXISTS "userapplication" (
          "nameapp"   TEXT NOT NULL,
          "user_app"   TEXT NOT NULL,
          "password"   TEXT,
          "email_in_app"    TEXT,
          "creationdate"    NUMERIC,
          "username"   TEXT,
          CONSTRAINT "user_info_app" FOREIGN KEY("nameapp") REFERENCES "infoapplication" ("nameapp") ON DELETE NO ACTION ON UPDATE NO ACTION,
          CONSTRAINT "user_create_record" FOREIGN KEY("username") REFERENCES "account"("username") ON DELETE CASCADE ON UPDATE CASCADE
          );""")

# This creates table for ifuserapp
    c.execute("""CREATE TABLE IF NOT EXISTS "ifuserapp" (
          "nameapp"   TEXT,
          CONSTRAINT "nameappofperson" FOREIGN KEY("nameapp") REFERENCES "infoapplication"("nameapp")
          );""")
    
    #this creates for user info
    c.execute("""CREATE TABLE IF NOT EXISTS "userinfo" (
          "personid" INTEGER PRIMARY KEY AUTOINCREMENT,
          "firstname"   TEXT,
          "lastname"   TEXT,
          "email"   TEXT,
          "phone"   TEXT
          );""")
    db.commit()
    db.close()

def get_database_path():
    return "data/manageapp.db"
