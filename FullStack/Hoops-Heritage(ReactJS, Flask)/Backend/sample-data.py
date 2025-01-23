import sqlite3
import bcrypt

def connect_to_db():
    """Establishes a connection to the SQLite database."""
    return sqlite3.connect('db/Project.db')

def populate_sample_data():
    try:
        conn = connect_to_db()
        cursor = conn.cursor()

        # Sample data for Admins
        admins = [
            ("admin1", bcrypt.hashpw("password1".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')),
            ("admin2", bcrypt.hashpw("password2".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')),
            ("admin3", bcrypt.hashpw("password3".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')),
        ]
        cursor.executemany('INSERT OR IGNORE INTO admins (username, password_hash) VALUES (?, ?);', admins)

        # Sample data for Roles
        roles = ["Inventory Manager", "Order Manager", "Product Manager"]
        cursor.executemany('INSERT OR IGNORE INTO roles (name) VALUES (?);', [(role,) for role in roles])

        # Sample data for Admin Roles
        admin_roles = [
            (1, 1),  # admin1 -> Inventory Manager
            (1, 2),  # admin1 -> Order Manager
            (1, 3),  # admin1 -> Product Manager
            (2, 2),  # admin2 -> Order Manager
            (2, 3),  # admin2 -> Inventory Manager
            (3, 3),  # admin3 -> Product Manager

        ]
        cursor.executemany('INSERT OR IGNORE INTO admin_roles (admin_id, role_id) VALUES (?, ?);', admin_roles)

        # Sample data for Products (with Discount and DiscountedPrice)
        products = [
            ("Basketball Jersey", 1, "Current-Era", 49.99, "Premium basketball jersey", "image1.jpg", 10.0),
            ("Vintage Sneakers", 2, "Vintage", 89.99, "Classic basketball sneakers", "image2.jpg", 15.0),
            ("Retro Cap", 3, "Retro", 19.99, "Stylish retro cap", "image3.jpg", 5.0),
            ("Hall of Fame Poster", 4, "Classics", 14.99, "Poster of legendary players", "image4.jpg", 20.0),
        ]
        cursor.executemany('''
            INSERT OR IGNORE INTO Products (Name, TeamId, Category, Price, Description, Image, Discount)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        ''', products)

        # Sample data for Customers
        customers = [
            ("John Doe", "john@example.com", "1234567890", "123 Basketball St", 100.0, "johndoe",
             bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 1, "Rookie"),
            ("Jane Smith", "jane@example.com", "0987654321", "456 Hoop Ave", 200.0, "janesmith",
             bcrypt.hashpw("securepass".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), 0, "All-Star"),
        ]
        cursor.executemany('''
            INSERT OR IGNORE INTO Customers (Name, Email, Phone, Address, Wallet, username, Password, Logged_in, Tier)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        ''', customers)

        # Sample data for Orders (TotalPrice based on discount)
        orders = [
            (1, 1, 1, 49.99 * (1 - 0.10), "Processing"),  # Product with 10% discount
            (2, 2, 2, 89.99 * (1 - 0.15), "Shipped"),    # Product with 15% discount
        ]
        cursor.executemany('''
            INSERT OR IGNORE INTO Orders (CustomerID, ProductID, WarehouseNumber, TotalPrice, Status)
            VALUES (?, ?, ?, ?, ?);
        ''', orders)

        # Sample data for Warehouse
        warehouse = [
            (1, 1, 1, 50),
            (2, 2, 2, 30),
            (3, 3, 3, 100),
            (4, 4, 4, 20),
        ]
        cursor.executemany('''
            INSERT OR IGNORE INTO Warehouse (WarehouseID, WarehouseNumber, ProductID, Stock)
            VALUES (?, ?, ?, ?);
        ''', warehouse)

        # Sample data for Wishlist
        wishlist = [
            (1, 2),
            (2, 3),
        ]
        cursor.executemany('INSERT OR IGNORE INTO Wishlist (CustomerID, ProductID) VALUES (?, ?);', wishlist)

        # Sample data for Popular products
        popular = [
            (1, 100),
            (2, 150),
            (3, 50),
        ]
        cursor.executemany('INSERT OR IGNORE INTO Popular (ProductID, Sold) VALUES (?, ?);', popular)

        # Commit changes
        conn.commit()
        print("Sample data successfully inserted into the database.")

    except sqlite3.Error as e:
        print(f"Error inserting sample data: {e}")
    finally:
        conn.close()

# Run the function to populate the database
populate_sample_data()

def fetch_and_print_table_content(table_name):
    """
    Fetches and prints the content of a table.
    :param table_name: Name of the table to fetch data from.
    """
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
        conn.close()

fetch_and_print_table_content('Products')
fetch_and_print_table_content('Orders')
fetch_and_print_table_content('Customers')
fetch_and_print_table_content('Warehouse')
fetch_and_print_table_content('Popular')

