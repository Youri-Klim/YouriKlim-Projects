import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS

def connect_to_db():
 """
    Establishes a connection to the SQLite database.
    """
 conn = sqlite3.connect('Project.db')
 return conn

def create_product_table():
    """
    Creates the 'Inventory' table in the database if it does not exist.
    Raises sqlite3.Error: If an error occurs during table creation.

    """
    try:
        conn = connect_to_db()
        conn.execute('''
                    CREATE TABLE Products (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Name TEXT NOT NULL,
                    TeamId INT NOT NULL,
                    category VARCHAR(15),
                    Price FLOAT NOT NULL,
                    Description TEXT NOT NULL,
                    Image VARBINARY(1000000),
                    CHECK (category IN ('Current-Era', 'Classics', 'Vintage', 'Retro')),
                    CHECK (TeamID <= 30)
                    );
                ''')
        conn.commit()
        print("Products created successfully")
    
    except sqlite3.Error as e:
        print("Products creation failed - ", e)
    finally:
        conn.close()

def create_db_popular():
    """
    Creates the 'Popular' table in the database if it does not exist.
    Raises sqlite3.Error: If an error occurs during table creation.

    """
    try:
        conn = connect_to_db()
        conn.execute('''
                    CREATE TABLE Popular (
                    ProductID INT PRIMARY KEY NOT NULL,
                    Sold INT DEFAULT 0,
                    FOREIGN KEY(ProductID) references Products(Id) ON DELETE CASCADE
                    );
                ''')
        conn.commit()
        print("Good table created successfully")
    
    except sqlite3.Error as e:
        print("Good table creation failed - ", e)
    finally:
        conn.close()

def create_db_warehouse():
    """
    Creates the 'Warehouse' table in the database if it does not exist.
    Raises sqlite3.Error: If an error occurs during table creation.

    """
    try:
        create_product_table()
        create_db_popular()
        conn = connect_to_db()
        conn.execute('''
                    CREATE TABLE Warehouse (
                    WarehouseID INT PRIMARY KEY NOT NULL,
                    WarehouseNumber INT,
                    ProductID INT,
                    Stock INT DEFAULT 0,
                    FOREIGN KEY (ProductID) REFERENCES Products(ID) ON DELETE CASCADE
                    );
                ''')
        conn.commit()
        print("Good table created successfully")
    
    except sqlite3.Error as e:
        print("Good table creation failed - ", e)
    finally:
        conn.close()


create_product_table()
create_db_popular()
create_db_warehouse()
