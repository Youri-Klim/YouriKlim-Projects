from flask import Flask, request, jsonify, send_from_directory, session, flash, redirect, url_for, render_template, current_app
from flask_wtf import CSRFProtect, FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from wtforms import StringField, FloatField, TextAreaField, SelectField, IntegerField, FileField
from wtforms.validators import InputRequired, NumberRange, DataRequired
from werkzeug.utils import secure_filename, safe_join
from urllib.parse import urlparse, urljoin
from socket import gethostbyname
import sqlite3
import requests
import socket
import os
import magic 
import jwt
import csv
import shutil
import imghdr
import re
import ipaddress
from datetime import datetime, timedelta
from functools import wraps
import logging
import bcrypt



app = Flask(__name__)
CORS(app)


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Log to a file
        logging.StreamHandler()          # Log to the console
    ]
)
logger = logging.getLogger(__name__)

#need to secure against Cross-Site Request Forgery atttacks
#can use flask FLASK-WTF extension which is used to protect against cross-site requests for forms
app.config['SECRET_KEY'] = 'LeBron_The_GoAt_JAMES' 
#CSRF = CSRFProtect(app) #enable CSRF protection


#file upload mitigation
ALLOWED_FILE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'csv'} #Allowed types of file extensions to be uploaded
ALLOWED_MIME_TYPES = {'Image/jpeg', 'Image/png', 'Image/gif' , 'text/csv'} #Allowed MIME Types that can be used
MAX_CONTENT_LENGTH =  7 * 1024 * 1024 #maximum file size is 7 MB

app.config['UPLOAD_FOLDER'] ="/static/other_files"
app.config['IMAGE_UPLOAD_FOLDER'] = '/static/images' #adding app.config in order to acess this directory all over the application
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

os.makedirs("/static/other_files", exist_ok=True)

class ProductForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    team_id = IntegerField('Team ID', validators=[DataRequired(), NumberRange(min=1, max=30)])
    category = SelectField('Category', choices=[('Current-Era', 'Current-Era'), ('Classics', 'Classics'), ('Vintage', 'Vintage'), ('Retro', 'Retro')], validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired(), NumberRange(min=0)])
    discount = FloatField('Discount (%)', validators=[NumberRange(min=0, max=100)], default=0) 
    discounted_price = FloatField('Discounted Price', render_kw={'readonly': True})  
    description = TextAreaField('Description', validators=[DataRequired()])
    image = FileField('Product Image')


def connect_to_db():
    conn = sqlite3.connect('db/Project.db')
    conn.row_factory = sqlite3.Row
    return conn


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing or invalid!'}), 401

        token = token.split(' ')[1]  # Strip 'Bearer'
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = data['username']
            current_roles = data['roles']
            return f(current_user, current_roles, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token!'}), 401
    return decorator

def requires_role(roles):
    def decorator(f):
        @wraps(f)
        @token_required  # Ensure token validation
        def wrapper(current_user, current_roles, *args, **kwargs):
            if any(role in current_roles for role in roles):
                return f(current_user, current_roles, *args, **kwargs)  # Authorized
            return jsonify({'error': 'Permission denied!'}), 403
        return wrapper
    return decorator



@app.route('/login', methods=['POST'])
def login():
    authenticate = request.json
    username = authenticate.get('username')
    password = authenticate.get('password')

    with connect_to_db() as conn:
        admin = conn.execute("SELECT * FROM admins WHERE username = ?", (username,)).fetchone()

        if admin and bcrypt.checkpw(password.encode('utf-8'), admin["password_hash"].encode('utf-8')):
            # Fetch roles assigned to the user
            roles = [
                role["name"]
                for role in conn.execute(
                    "SELECT r.name FROM roles r JOIN admin_roles ar ON r.id = ar.role_id WHERE ar.admin_id = ?",
                    (admin["id"],)
                ).fetchall()
            ]

            token = jwt.encode({
                'username': username,
                'roles': roles,
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            logger.info(f"User {username} logged in successfully with roles: {roles}")
            return jsonify({'token': token, 'roles': roles}), 200

    logger.warning(f"Login failed for user {username}.")
    return jsonify({'error': 'Invalid credentials'}), 401


#check if uploaded file is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_FILE_EXTENSIONS

#securing the file upload
@app.route('/upload', methods=['POST'])
def upload_a_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file available'}), 500
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No filename has been entered'}), 500
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file extension, File extension used is not allowed'}), 500

    #need to secure the file name and Verify the mime type of the file by using Python magic
    filename = secure_filename(file.filename) #secure_file name cleans the filename before saving it ie it removes special characters and replaces spaces 
    MIME_TYPE = magic.Magic(mime=True)
    Files_MIME_TYPE = MIME_TYPE.from_buffer(file.read(1024)) #reading the first 1024 bytes
    
    if Files_MIME_TYPE not in ALLOWED_MIME_TYPES:
        return jsonify({'error': 'Invalid MIME Type, File type used is not allowed'}), 500
    
    #resetting the pointer and saving the file
    file.seek(0)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    
    return jsonify({'message': 'File has uploaded successfully'}), 200
    
#providing access to the file upload folder:
@app.route('/uploads/<filename>')
def serve_file(filename):
    safe_path = safe_join(app.config['UPLOAD_FOLDER'], filename)
    if safe_path and os.path.isfile(safe_path):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    else:
        return jsonify({'error': 'File not found'}), 404 #error 404 not found :)
        
#creating an allow list for trusted applications for ssrf: (whitelist)
app.config['ALLOWED_DOMAINS'] = ['trusted-supplier.com', 'localhost', 'http://localhost:5000', 'http://127.0.0.1:5000']
app.config['ALLOWED_IPS'] = ['127.0.0.1', '127.0.0.1:5000']  

URL_REGEX = re.compile(
    r'^(https?):\/\/'  # Scheme
    r'([a-zA-Z0-9.-]+)'  # Domain or IP address
    r'(\/[^\s]*)?'  # Path
    r'$', re.IGNORECASE
)

def URL_allowed(url):
    """Validates the URL against the regex pattern and checks the domain/IP."""
    # Step 1: URL format validation
    if not URL_REGEX.match(url):
        return False
    # Domain validation
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    if not domain in Allowed_Application:
        return False
    # Step 3: IP address validation
    try:
        ip = gethostbyname(domain)
        return ip in current_app.config['ALLOWED_IPS']
    except Exception as e:
        print(f"Failed to resolve IP for domain {domain}: {e}")
        return False

def add_image_securely(image_path):
    # Secure the filename to avoid path traversal issues
    image_filename = secure_filename(os.path.basename(image_path))
    # Set the destination path for the image
    image_dest = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
    # Check if the file is an image by examining its type

    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(image_path) 
    if mime_type not in ALLOWED_MIME_TYPES:
        raise ValueError(f"File at {image_path} has an invalid MIME type: {mime_type}")

    # Check if the file has an allowed extension
    file_extension = os.path.splitext(image_filename)[1].lower()[1:]
    if file_extension not in ALLOWED_FILE_EXTENSIONS:
        raise ValueError(f"Image at {image_path} has an invalid file extension: {file_extension}")

    if not imghdr.what(image_path):
        raise ValueError(f"File at {image_path} is not a valid image.")
    if imghdr.what(image_path) not in ALLOWED_FILE_EXTENSIONS:
        raise ValueError(f"Image at {image_path} is not an allowed type.")
    # Copy the image securely to the upload folder
    shutil.copy(image_path, image_dest)


@app.route('/fetch data', methods=['POST'])
def fetch_data():
    data = request.json
    url = data.get('url')

    #check if url is allowed 
    if not URL_allowed(url):
        return jsonify({'error': 'URL not allowed'}), 403 #403 is for forbidden
    else:
        return jsonify({'Valid': 'URL is allowed to safely acccess'}), 200 

############################################################################################
######################## Inventory Managment #################################################
############################################################################################
@app.route('/inventory', methods=['GET'])
@requires_role(["Inventory Manager"])
def get_inventory(current_user, current_roles):
    logger.info("Inventory Manager accessed the get inventory backend.")

    try:
        conn = connect_to_db()
        cursor = conn.execute('''
            SELECT 
            Products.Id, 
            Products.Name, 
            Warehouse.WarehouseNumber, 
            SUM(Warehouse.Stock) AS TotalStock
            FROM Products
            JOIN Warehouse ON Products.Id = Warehouse.ProductID
            GROUP BY Products.Id, Products.Name, Warehouse.WarehouseNumber
''')

        products = [dict(row) for row in cursor.fetchall()]
        return jsonify(products), 200 #200 represents that the products were found 
    except Exception as e:
        return jsonify({'error': str(e)}), 500 #500 is for internal server error
    finally:
        conn.close()
#Updating the stocks for a certain product:
@app.route('/inventory/update/<int:warehouse_number>/<int:product_id>', methods=['POST'])
@requires_role(["Inventory Manager"])
def update_stock(current_user, current_roles,warehouse_number, product_id):
    logger.info("Inventory Manager accessed the update stock backend.")

    new_stock = request.json.get('stock')
    try:
        conn = connect_to_db()  # parameterized query
        conn.execute('''
            UPDATE Warehouse
            SET Stock = ?
            WHERE ProductID = ? AND WarehouseNumber = ?
        ''', (new_stock, product_id, warehouse_number))
        conn.commit()
        return jsonify({'message': 'Stock updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

#Checking if a products stock is low (creating an alert for low stock levels)
@app.route('/inventory/low_stock_alert', methods=['GET'])
@requires_role(["Inventory Manager"])
def low_stock_alert(current_user, current_roles):
    logger.info("Inventory Manager accessed the low stock alert backend.")

    threshold_low_stock = 50  # Setting a minimum number by which if we go under it then our stock is considerd low.
    try:
        conn = connect_to_db()
        cursor = conn.execute('''
            SELECT Products.Name, Warehouse.Stock, Warehouse.WarehouseNumber
 	        FROM Products
            JOIN Warehouse ON Products.Id = Warehouse.ProductID
            WHERE Warehouse.Stock < ?
	    ''', (threshold_low_stock,))
        low_stock_products = [dict(row) for row in cursor.fetchall()]
        if not low_stock_products:
            return jsonify({'message': 'All products Have a good amount stocked'}), 200
        return jsonify({'low_stock_products': low_stock_products}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

#Getting an inventory report for Admins:

@app.route('/inventory/report', methods=['GET'])
@requires_role(["Inventory Manager"])
def generate_inventory_report(current_user, current_roles):
    logger.info("Inventory Manager accessed the generate inventory report backend.")

    try:
        conn = connect_to_db()
        cursor = conn.execute('''
            SELECT Products.Name, SUM(Warehouse.Stock) AS TotalStock, Popular.Sold
            FROM Products
            JOIN Warehouse ON Products.Id = Warehouse.ProductID
            LEFT JOIN Popular ON Products.Id = Popular.ProductID
            GROUP BY Products.Id
            ORDER BY Popular.Sold DESC
        ''')
        report = [dict(row) for row in cursor.fetchall()]
        return jsonify(report), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
############################################################################################
######################## Order Managment #################################################
############################################################################################
@app.route('/create_orders', methods=['POST'])
@requires_role(["Order Manager"])
def create_order(current_user, current_roles):
    logger.info("Order Manager accessed the create order backend.")

    data = request.json
    customer_id = data.get('customer_id')  # Corrected key name
    product_id = data.get('product_id')  # Corrected key name
    warehouse_number = data.get('WarehouseNumber')  # Corrected key name
    total_price = data.get('total_price')
    status = 'Pending'  # Default status

    try:
         conn = connect_to_db()
         conn.execute('''
            INSERT INTO Orders (CustomerID, ProductID, WarehouseNumber, TotalPrice, Status)
            VALUES (?, ?, ?, ?, ?)
        ''', (customer_id, product_id, warehouse_number, total_price, status)) #? are replaced with values ie first ? is CustomerID etc (parametrized query since the Db will treat the inputs as data)
         conn.commit()
         return jsonify({'message': 'Order was placed succesfully'}), 200 #commit the transaction once it is sucsseful 
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
#updating Order status 

@app.route('/orders/<int:order_id>/status', methods=['PUT'])
@requires_role(["Order Manager"])
def update_order_status(current_user, current_roles,order_id):

    logger.info("Order Manager accessed the update order status backend.")

    new_status = request.json.get('status')
    #were going to use an array of allowed values in order to prevent sql injection and command injection as we allow only a specific set of values to be inputted
    allowed_statuses = ['Pending', 'Processing', 'Shipped', 'Refunded', 'Exchanged']  

    if new_status not in allowed_statuses:#if the value is not within our allowed array then we should deny the input and cause an error
        return jsonify({'error': 'Invalid status'}), 500

    try:
        conn = connect_to_db() #parametrized query
        conn.execute('''      
            UPDATE Orders
            SET Status = ?
            WHERE OrderID = ?
        ''', (new_status, order_id))
        conn.commit()
        return jsonify({'message': 'Order status updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/orders', methods=['GET'])
@requires_role(["Order Manager"])
def get_orders(current_user, current_roles):
    logger.info("Order Manager accessed the get order backend.")

    try:
        conn = connect_to_db()
        cursor = conn.execute('''
            SELECT OrderID, CustomerID, ProductID, WarehouseNumber, TotalPrice, Status
            FROM Orders
        ''')
        orders = [
            {
                "order_id": row["OrderID"],
                "customer_id": row["CustomerID"],
                "product_id": row["ProductID"],
                "warehouse_id": row["WarehouseNumber"],
                "total_price": row["TotalPrice"],
                "status": row["Status"]
            }
            for row in cursor.fetchall()
        ]
        
        if not orders:
            return jsonify({"message": "No orders found"}), 404

        return jsonify(orders), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


@app.route('/orders/<int:order_id>/request-return', methods=['PUT']) ### Fixed the function
@requires_role(["Order Manager"])
def request_return(current_user, current_roles,order_id):
    """
    Initiates a return request by setting the order status to 'Refunded' or 'Exchanged'
    and then calls manage_return to handle the return processing.
    """
    logger.info("Order Manager accessed the request returns backend.")

    new_status = request.json.get('status')  # 'Refunded' or 'Exchanged'

    allowed_statuses = ['Pending', 'Processing', 'Shipped']

    # Ensure the status is valid before proceeding
    if new_status not in allowed_statuses:
        return jsonify({'error': 'Invalid status for return'}), 400

    try:
        conn = connect_to_db()  # parametrized query
        conn.execute('''
            UPDATE Orders
            SET Status = ?
            WHERE OrderID = ?
        ''', (new_status, order_id))
        conn.commit()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

    # Call manage_return after successfully updating the status
    manage_response = manage_return(order_id, new_status)
    if manage_response.get('error'):
        return jsonify({'error': 'Return management failed'}), 500

    return jsonify({'message': 'Return request managed successfully'}), 200


@app.route('/orders/<int:order_id>/manage-return', methods=['PUT'])
@requires_role(["Order Manager"])
def manage_return(current_user, current_roles,order_id, new_status):
    """
    Manages the return processing based on the current status of the order ('Refunded' or 'Exchanged').
    If 'Refunded', it updates the wallet, warehouse, and popularity. 
    If 'Exchanged', it creates a new order and updates the warehouse stock.
    """
    logger.info("Order Manager accessed the manage returns backend.")

    try:
        conn = connect_to_db()
        cursor = conn.cursor()

        # Get the order and related details
        order = cursor.execute('SELECT ProductID, CustomerID, TotalPrice, Status FROM Orders WHERE OrderID = ?', (order_id,)).fetchone()
        if not order:
            return jsonify({'error': 'Order not found'}), 404

        product_id, customer_id, warehouse_id, total_price, order_status = order

        # Check the current order status and apply logic based on 'Refunded' or 'Exchanged'
        if new_status == 'Refunded':
            # Increase stock by 1 in the Warehouse table
            cursor.execute('UPDATE Warehouse SET Stock = Stock + 1 WHERE ProductID = ? AND WarehouseNumber = ?',
                           (product_id, warehouse_id))

            # Add refund amount to the customer's wallet
            cursor.execute('UPDATE Customers SET Wallet = Wallet + ?WHERE CustomerID = ?',
                           (total_price, customer_id))

            # Deduct popularity for the specific product in the Popular table
            cursor.execute('UPDATE Popular SET Sold = Sold - 1 WHERE ProductID = ?',
                           (product_id,))

            message = 'Refund processed successfully'

        elif new_status == 'Exchanged':

            # Add refund amount to the customer's wallet
            cursor.execute('UPDATE Customers  SET Wallet = Wallet + ?WHERE CustomerID = ?',
                           (total_price, customer_id))
            
            # Increase stock by 1 in the Warehouse table
            cursor.execute('UPDATE Warehouse SET Stock = Stock + 1 WHERE ProductID = ? AND WarehouseNumber = ?', 
                            (product_id, warehouse_id))

            new_product_id = request.json.get('product_id')

            new_total = cursor.execute('''
                           SELECT Price FROM Products
                           WHERE Id = ?
                          ''', (new_product_id))

            # Create a new order with the same details as the old order and status set to 'Pending'
            cursor.execute('''
                INSERT INTO Orders (CustomerID, ProductID, TotalPrice, Status)
                VALUES (?, ?, ?, 'Pending')
            ''', (customer_id, new_product_id, new_total))

            message = 'Replacement processed successfully and new order created'

        else:
            return jsonify({'error': 'Invalid status for return management'}), 400

        conn.commit()
        return jsonify({'message': message}), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

############################################################################################
######################## Product Managment #################################################
############################################################################################


#viewing the products
@app.route("/products", methods=["GET"])
@requires_role(["Product Manager"])
def list_products(current_user, current_roles):
    """
    List all products with optional filters, sorting, 
    and dynamic discounted price handling.
    """
    logger.info("Product Manager accessed the list products backend")
    
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    min_discounted_price = request.args.get('min_discounted_price', type=float)
    max_discounted_price = request.args.get('max_discounted_price', type=float)
    min_discount = request.args.get('min_discount', type=float)
    max_discount = request.args.get('max_discount', type=float)
    team_id = request.args.get('team_id', type=int)
    category = request.args.get('category', type=str)
    sort_by = request.args.get('sort_by', 'Name')  # Default sort by Name
    order = request.args.get('order', 'asc')  # Default to ascending order

    # Whitelist 
    valid_sort_columns = {'Name', 'Price', 'Discount', 'DiscountedPrice'}
    if sort_by not in valid_sort_columns:
        return jsonify({"error": "Invalid sort column"}), 400
    if order not in {'asc', 'desc'}:
        return jsonify({"error": "Invalid sort order"}), 400

    # Base SQL query with dynamic discounted price calculation
    query = """
        SELECT 
            Id, Name, TeamId, Category, Price, Discount, 
            Description, Image, DiscountedPrice
        FROM Products 
        WHERE 1=1
    """
    params = []
    print("this is the query before the filters")
    print(query)

    # Apply filters only if provided
    if min_price is not None:
        query += " AND Price >= ?"
        params.append(min_price)
    if max_price is not None:
        query += " AND Price <= ?"
        params.append(max_price)
    if min_discounted_price is not None:
        query += " AND DiscountedPrice >= ?"
        params.append(min_discounted_price)
    if max_discounted_price is not None:
        query += " AND DiscountedPrice <= ?"
        params.append(max_discounted_price)
    if min_discount is not None:
        query += " AND Discount >= ?"
        params.append(min_discount)
    if max_discount is not None:
        query += " AND Discount <= ?"
        params.append(max_discount)
    if team_id is not None:
        query += " AND TeamId = ?"
        params.append(team_id)
    if category:
        query += " AND Category = ?"
        params.append(category)
    print("this is the query after the filters")
    print(query)
    # Add sorting
    query += f" ORDER BY {sort_by} {'ASC' if order == 'asc' else 'DESC'}"
    print("this is the query after order by")
    print(query)


    # Execute the query
    with connect_to_db() as conn:
        products = conn.execute(query, params).fetchall()

    # Convert the results to a list of dictionaries
    products_list = [dict(product) for product in products]

    # Return the products list in JSON format
    return jsonify(products_list), 200


# Viewing a single product by ID
@app.route("/products/<int:product_id>", methods=["GET"])
@requires_role(["Product Manager"])
def get_product(current_user, current_roles, product_id):
    """
    Retrieve a single product by its ID.
    """
    logger.info(f"Product Manager accessed the product details for product ID {product_id}")
    
    # SQL query to fetch the product by ID
    query = """
        SELECT 
            Id, Name, TeamId, Category, Price, Discount, 
            Description, Image, DiscountedPrice 
        FROM Products 
        WHERE Id = ?
    """
    
    # Execute the query
    with connect_to_db() as conn:
        product = conn.execute(query, (product_id,)).fetchone()

    # Check if the product exists
    if product is None:
        return jsonify({"error": "Product not found"}), 404

    # Convert the result to a dictionary
    product_data = dict(product)
    
    logger.debug(f"Fetched product: {product_data}")


    # Return the product data in JSON format
    return jsonify(product_data), 200

# adding products
@app.route('/products', methods=['POST'])
@requires_role(["Product Manager"])
def add_product(current_user, current_roles):
    logger.info("Product Manager accessed the add product backend")

    name = request.form.get('name')
    team_id = request.form.get('team_id')
    category = request.form.get('category')
    price = float(request.form.get('price'))  # Convert to float since the form sends it as a string
    description = request.form.get('description')
    discount = float(request.form.get("discount", 0))  # Default to 0 if not provided
    image_path = request.files.get('image')  # This will handle the uploaded file

    if not all([name, team_id, category, price, description]):
        return jsonify({'error': 'Missing required fields'}), 400

    if price < 0 or not (0 <= discount <= 100):
        return jsonify({"error": "Invalid price or discount"}), 400

    # Securely handle image upload (if provided)
    filename = None
    if image_path and allowed_file(image_path):
        try:
            add_image_securely(image_path)
            filename = image_path
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    try:
        query = '''
            INSERT INTO Products (Name, TeamId, Category, Price, Discount, Description, Image)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        params = (name, team_id, category, price, discount, description, filename)

        with connect_to_db() as conn:
            conn.execute(query, params)
            conn.commit()
        return jsonify({'message': 'Product added successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

#update products
@app.route('/update-products/<int:product_id>', methods=['PUT'])
@requires_role(["Product Manager"])
def update_product(current_user, current_roles,product_id):
    logger.info("Product Manager accessed the update product backend")

    with connect_to_db() as conn:
        product = conn.execute("SELECT * FROM Products WHERE Id = ?", (product_id,)).fetchone()

    if not product:
        return jsonify({"error": "Product not found"}), 404

    data = request.form
    image = request.files.get('image')


    updates = {}

    # Check and update each field only if it's changed
    if "name" in data and data["name"] != product["Name"]:
        updates["Name"] = data["name"]

    if "team_id" in data and data["team_id"] != product["TeamId"]:
        updates["TeamId"] = data["team_id"]

    if "category" in data and data["category"] != product["Category"]:
        updates["Category"] = data["category"]

    if "price" in data and data["price"] != product["Price"]:
        updates["Price"] = data["price"]

    if "description" in data and data["description"] != product["Description"]:
        updates["Description"] = data["description"]

    if "discount" in data and data["discount"] != product["Discount"]:
        updates["Discount"] = data["discount"]


    if image and allowed_file(image):
        try:
            add_image_securely(image)
            updates['Image'] = image
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    if updates:
        query = "UPDATE Products SET " + ", ".join([f"{key} = ?" for key in updates.keys()]) + " WHERE Id = ?"
        params = list(updates.values()) + [product_id]

        with connect_to_db() as conn:
            conn.execute(query, params)
            conn.commit()

    return jsonify({"message": "Product updated successfully"}), 200


#remove products
@app.route('/delete-products/<int:product_id>', methods=['DELETE'])
@requires_role(["Product Manager"])
def delete_product(current_user, current_roles,product_id):
    logger.info("Product Manager accessed the delete product backend")

    try:
        conn = connect_to_db()
        conn.execute('DELETE FROM Products WHERE Id = ?', (product_id,))
        conn.commit()
        return jsonify({'message': 'Product deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()


#Bulk Upload CSV_files
@app.route('/product_bulk_upload_csv', methods=['POST'])
@requires_role(["Product Manager"])
def upload_csv_backend(current_user, current_roles):
    """Backend service to upload products via CSV."""
    logger.info("Product Manager accessed the upload csv backend")

    file = request.files.get('file')

    if not file or not allowed_file(file.filename):
        return jsonify({"error": "Please upload a valid CSV file"}), 400

    filename = secure_filename(file.filename) #secure_file name cleans the filename before saving it ie it removes special characters and replaces spaces 
    MIME_TYPE = magic.Magic(mime=True)
    Files_MIME_TYPE = MIME_TYPE.from_buffer(file.read(1024)) #reading the first 1024 bytes
    
    if Files_MIME_TYPE not in ALLOWED_MIME_TYPES:
        return jsonify({'error': 'Invalid MIME Type, File type used is not allowed'}), 500
    
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    with open(filepath, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        required_fields = {'name', 'teamid', 'category', 'price', 'discount', 'description', 'image_directory'}
        if not required_fields.issubset(reader.fieldnames):
            return jsonify({"error": f"CSV file is missing required columns: {', '.join(required_fields)}"}), 400

        conn = connect_to_db()
        for row in reader:
            try:
                name = row['name']
                team_id = int(row['teamid'])
                category = row['category']
                price = float(row['price'])
                discount = float(row['discount'])
                description = row['description']
                image_path = row['image_directory']

                if image_path and allowed_file(image_path):
                    image_path = add_image_securely(image_path)
                else:
                    image_path = None

                conn.execute('''
                    INSERT INTO Products (Name, TeamId, Category, Price, Discount, Description, Image)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (name, team_id, category, price, discount, description, image_path))
            except Exception as e:
                conn.rollback()
                return jsonify({"error": f"Failed to process row: {row}. Error: {str(e)}"}), 500

        conn.commit()
        conn.close()

    return jsonify({"message": "Products uploaded successfully from CSV"}), 201

 

    
@app.route("/api/products/supplier", methods=["GET"])
@requires_role(["Product Manager"])
def fetch_supplier_products_backend(current_user, current_roles):
    """Backend service to fetch supplier products securely."""
    logger.info("Product Manager accessed the supplier products backend")

    supplier_url = app.config['SUPPLIER_API_URL']
    # SSRF protection: Validate the URL
    if not URL_allowed(supplier_url):
        return jsonify({"error": "Invalid or unauthorized supplier URL"}), 403

    headers = {
        'Authorization': f'Bearer {app.config["JWT_SUPPLIER_TOKEN"]}',
        'Accept': 'application/json',
    }

    try:
        # Fetch supplier products with a timeout and prevent redirects
        response = requests.get(supplier_url, headers=headers, timeout=10, allow_redirects=False)
        response.raise_for_status()

        if response.headers.get('Content-Type') != 'application/json':
            return jsonify({"error": "Unexpected content type from supplier"}), 400

        products = response.json()
        return jsonify(products), 200

    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch supplier products: {e}")
        return jsonify({"error": "Failed to fetch supplier data"}), 500


if __name__ == '__main__': 
    app.run(debug=True, port=4000)
