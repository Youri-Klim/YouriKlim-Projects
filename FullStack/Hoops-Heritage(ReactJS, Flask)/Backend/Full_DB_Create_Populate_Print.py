import sqlite3
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt

def connect_to_db():
 """
    Establishes a connection to the SQLite database.
    """
 conn = sqlite3.connect('db/Project.db')
 return conn


def create_db_popular():
    """
    Creates the 'Popular' table in the database if it does not exist.
    Raises sqlite3.Error: If an error occurs during table creation.

    """
    conn = None
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
        if conn:
            conn.close()

def create_db_warehouse():
    """
    Creates the 'Warehouse' table in the database if it does not exist.
    Raises sqlite3.Error: If an error occurs during table creation.

    """
    conn = None
    try:
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
        if conn:
            conn.close()

def create_db_customers():
    """
    Creates the 'Customers' table in the database if it does not exist.
    Raises sqlite3.Error: If an error occurs during table creation.
    """
    conn = None
    try:
        conn = connect_to_db()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS Customers (
                CustomerID INTEGER PRIMARY KEY AUTOINCREMENT,
                Name TEXT NOT NULL,
                Email TEXT UNIQUE NOT NULL,
                Phone TEXT,
                Address TEXT,
                Wallet REAL DEFAULT 0.0,
                username TEXT NOT NULL,
                Password TEXT NOT NULL,
                Logged_in BOOLEAN DEFAULT 0,
                Tier TEXT DEFAULT 'No Tier' CHECK(Tier IN ('Rookie', 'All-Star', 'Hall Of Fame')),
                CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        conn.commit()
        print("Customers table created successfully")

    except sqlite3.Error as e:
        print("Customers table creation failed -", e)
    finally:
        if conn:
            conn.close()

def create_db_orders():
    """
    Creates the 'Orders' table in the database if it does not exist.
    Raises sqlite3.Error: If an error occurs during table creation.
    """
    conn = None
    try:
        conn = connect_to_db()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS Orders (
                OrderID INTEGER PRIMARY KEY AUTOINCREMENT,
                CustomerID INT NOT NULL,
                ProductID INT NOT NULL,
                WarehouseNumber INT NOT NULL,
                TotalPrice REAL NOT NULL,
                Status VARCHAR(15) DEFAULT 'Pending' CHECK (Status IN ('Pending', 'Delivered', 'Processing', 'Shipped', 'Refunded', 'Exchanged')),
                FOREIGN KEY (CustomerID) REFERENCES Customers(CustomerID) ON DELETE CASCADE,
                FOREIGN KEY (ProductID) REFERENCES Products(Id) ON DELETE CASCADE
                FOREIGN KEY (WarehouseNumber) REFERENCES Warehouse(WarehouseNumber) ON DELETE CASCADE
            );
        ''')
        conn.commit()
        print("Orders table created successfully")

    except sqlite3.Error as e:
        print("Orders table creation failed -", e)
    finally:
        if conn:
            conn.close()

def create_db_history():
    """
    Creates the 'History' table in the database to map customers to their orders.
    Raises sqlite3.Error: If an error occurs during table creation.
    """
    conn = None
    try:
        conn = connect_to_db()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS History (
                HistoryID INTEGER PRIMARY KEY AUTOINCREMENT,
                CustomerID INT NOT NULL,
                OrderID INT NOT NULL,
                OrderDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (CustomerID) REFERENCES Customers(CustomerID) ON DELETE CASCADE,
                FOREIGN KEY (OrderID) REFERENCES Orders(OrderID) ON DELETE CASCADE
            );
        ''')
        conn.commit()
        print("History table created successfully")

    except sqlite3.Error as e:
        print("History table creation failed -", e)
    finally:
        if conn:
            conn.close()

def create_db_wishlist():
    """
    Creates the 'Wishlist' table in the database to map customers to their desired products.
    Raises sqlite3.Error: If an error occurs during table creation.
    """
    conn = None
    try:
        conn = connect_to_db()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS Wishlist (
                WishlistID INTEGER PRIMARY KEY AUTOINCREMENT,
                CustomerID INT NOT NULL,
                ProductID INT NOT NULL,
                AddedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (CustomerID) REFERENCES Customers(CustomerID) ON DELETE CASCADE,
                FOREIGN KEY (ProductID) REFERENCES Products(Id) ON DELETE CASCADE
            );
        ''')
        conn.commit()
        print("Wishlist table created successfully")

    except sqlite3.Error as e:
        print("Wishlist table creation failed -", e)
    finally:
        if conn:
            conn.close()

def create_db_admins():
    conn = None
    try:
        conn = connect_to_db()
        # Create the admins table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        ''')
        # Create the roles table with restricted role names
        conn.execute('''
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        ''')
        # Create the admin_roles mapping table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admin_roles (
                admin_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                FOREIGN KEY (admin_id) REFERENCES admins (id),
                FOREIGN KEY (role_id) REFERENCES roles (id),
                UNIQUE (admin_id, role_id)
            )
        ''')

        conn.commit()
        print("Admins tables created successfully")

    except sqlite3.Error as e:
        print("Admins tables creation failed -", e)
    finally:
        if conn:
            conn.close()

def create_product_table():
    """
    Creates the 'Inventory' table in the database if it does not exist.
    Raises sqlite3.Error: If an error occurs during table creation.

    """
    conn = None
    try:
        conn = connect_to_db()
        conn.execute('''
                CREATE TABLE IF NOT EXISTS Products (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Name TEXT NOT NULL,
                    TeamId INT NOT NULL,
                    Category VARCHAR(15),
                    Price FLOAT NOT NULL,
                    Description TEXT NOT NULL,
                    Image TEXT,
                    Discount FLOAT DEFAULT 0,
                    DiscountedPrice FLOAT GENERATED ALWAYS AS (Price * (1 - Discount / 100)) STORED,
                    CHECK (category IN ('Current-Era', 'Classics', 'Vintage', 'Retro')),
                    CHECK (TeamId <= 30)
                );
                ''')
        conn.commit()
        print("Products created successfully")
    
    except sqlite3.Error as e:
        print("Products creation failed - ", e)
    finally:
        if conn:
            conn.close()


def create_default_roles():
    roles = ["Inventory Manager", "Order Manager", "Product Manager"]
    with connect_to_db() as conn:
        for role in roles:
            try:
                conn.execute("INSERT INTO roles (name) VALUES (?)", (role,))
            except sqlite3.IntegrityError:
                pass  # Skip if the role already exists
        conn.commit()


create_db_popular()
create_db_warehouse()
create_db_customers()
create_db_orders()
create_db_history()
create_db_wishlist()
create_db_admins()
create_product_table()
create_default_roles()
print()
print()

def fetch_and_print_table_content(table_name):
    """
    Fetches and prints the content of a table.
    :param table_name: Name of the table to fetch data from.
    """
    conn = None
    try:
        conn = connect_to_db()
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name};")
        rows = cursor.fetchall()

        if rows:
            print(f"Content of the '{table_name}' table:")
            for row in rows:
                print(row)
        else:
            print(f"The '{table_name}' table is empty.")
    except sqlite3.Error as e:
        print(f"Failed to fetch data from '{table_name}' - {e}")
    finally:
        if conn:
            conn.close()

fetch_and_print_table_content('Popular')
fetch_and_print_table_content('Warehouse')
fetch_and_print_table_content('Customers')
fetch_and_print_table_content('Orders')
fetch_and_print_table_content('History')
fetch_and_print_table_content('Wishlist')
fetch_and_print_table_content('admins')
fetch_and_print_table_content('Products')
fetch_and_print_table_content('roles')
