import sqlite3
import csv
import os
import shutil
import imghdr
import requests
import jwt
import re
import ipaddress
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, current_app, session
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, FloatField, TextAreaField, SelectField, IntegerField, FileField
from wtforms.validators import InputRequired, NumberRange, DataRequired
from werkzeug.utils import secure_filename
from functools import wraps
from urllib.parse import urlparse, urljoin
from socket import gethostbyname
from flask import Flask, render_template


app = Flask(__name__)
app.config['SECRET_KEY'] = 'LeBron_The_GoAt_JAMES' 

def parse_json_response(response):
    try:
        return response.json()
    except ValueError:
        return None
    


class ProductForm(FlaskForm):
    name = StringField('Name', validators=[])
    team_id = IntegerField('Team ID', validators=[ NumberRange(min=1, max=30)])
    category = SelectField('Category', choices=[('Current-Era', 'Current-Era'), ('Classics', 'Classics'), ('Vintage', 'Vintage'), ('Retro', 'Retro')], validators=[DataRequired()])
    price = FloatField('Price', validators=[NumberRange(min=0)])
    discount = FloatField('Discount (%)', validators=[NumberRange(min=0, max=100)], default=0) 
    discounted_price = FloatField('Discounted Price', render_kw={'readonly': True})  
    description = TextAreaField('Description', validators=[])
    image = FileField('Product Image')



BACKEND_URL = "http://localhost:4000"  


@app.route("/")
def home():
    return redirect("/login")  # Redirect to login by default


@app.route('/report')
def report():
    if "token" not in session:
        return redirect("/login")
    if "Inventory Manager" not in session.get("roles", []):
        flash("Access denied.", "danger")
        return redirect("/menu")

    return render_template('report.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        response = requests.post(f"{BACKEND_URL}/login", json={"username": username, "password": password})

        if response.status_code == 200:
            data = response.json()
            session["token"] = data["token"]  # Save the token in session
            session["roles"] = data["roles"]  # Save roles in session
            return redirect("/menu")
        else:
            flash("Invalid login credentials", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect("/login")


@app.route("/menu")
def menu():
    token = session.get("token")  # Retrieve the token from the session
    if token is None:
        flash("You need to log in first.", "danger")
        return redirect("/login")
    # Use the token to make an authenticated request
    headers = {"Authorization": f"Bearer {token}"}


    user_roles = session.get("roles", [])
    return render_template("menu.html", roles=user_roles)


@app.route('/inventory', methods=['GET', 'POST'])
def inventory():
    token = session.get("token")
    if not token:
        flash("You need to log in first.", "danger")
        return redirect("/login")

    headers = {"Authorization": f"Bearer {token}"}

    # Fetch inventory data
    inventory_data = []
    inventory_response = requests.get(f"{BACKEND_URL}/inventory", headers=headers)
    if inventory_response.status_code == 200:
        inventory_data = inventory_response.json()

    # Fetch low stock alerts
    low_stock_alerts = []
    low_stock_response = requests.get(f"{BACKEND_URL}/inventory/low_stock_alert", headers=headers)
    if low_stock_response.status_code == 200:
        low_stock_alerts = low_stock_response.json().get("low_stock_products", [])

    # Fetch inventory report
    inventory_report = []
    report_response = requests.get(f"{BACKEND_URL}/inventory/report", headers=headers)
    if report_response.status_code == 200:
        inventory_report = report_response.json()

    if request.method == 'POST':  # Handle stock updates
        warehouse_number = request.form.get("warehouse_number")
        product_id = request.form.get("product_id")
        stock = request.form.get("stock")

        update_response = requests.post(
            f"{BACKEND_URL}/inventory/update/{warehouse_number}/{product_id}",
            json={"stock": stock},
            headers=headers
        )

        if update_response.status_code == 200:
            flash("Inventory updated successfully!", "success")
        else:
            flash("Failed to update inventory.", "danger")

        return redirect("/inventory")
    
    if "Inventory Manager" not in session.get("roles", []):
        flash("Access denied.", "danger")
        return redirect("/menu")


    return render_template(
        "inventory.html",
        inventory=inventory_data,
        low_stock_alerts=low_stock_alerts,
        report=inventory_report
    )


@app.route('/order', methods=["GET", "POST", "PUT"])
def order():
    token = session.get("token")  # Retrieve the token from the session
    if token is None:
        flash("You need to log in first.", "danger")
        return redirect("/login")

    headers = {"Authorization": f"Bearer {token}"}

   
    data = {
        "customer_id": request.form.get("customer_id"),
        "product_id": request.form.get("product_id"),
        "WarehouseNumber": request.form.get("WarehouseNumber"),
        "total_price": request.form.get("total_price")
    }

    response = requests.post(f"{BACKEND_URL}/create_orders", json=data, headers=headers)

    # Update Order Status
    order_id = request.form.get("order_id")
    status = request.form.get("status")

    url = f"{BACKEND_URL}/orders/{order_id}/status"
    response = requests.put(url, json={"status": status}, headers=headers)

    # Get All Orders
    response = requests.get(f"{BACKEND_URL}/orders", headers=headers)
    orders = parse_json_response(response) if response.status_code == 200 else []
    print("All Orders Data:", orders)

    # Request Return
    response = requests.get(f"{BACKEND_URL}/orders/<int:order_id>/request-return", headers=headers)
    return_request = parse_json_response(response) if response.status_code == 200 else []
    print("Return Request Data:", return_request)

    # Check Role
    if "Order Manager" not in session.get("roles", []):
        flash("Access denied.", "danger")
        return redirect("/menu")

    return render_template('Order.html', orders=orders)


@app.route("/product")
def product_management_page():
    token = session.get("token")  # Retrieve the token from the session
    if token is None:
        flash("You need to log in first.", "danger")
        return redirect("/login")
    
    # Use the token to make an authenticated request
    headers = {"Authorization": f"Bearer {token}"}

    if "Product Manager" not in session.get("roles", []):
        flash("Access denied.", "danger")
        return redirect("/menu")
    
    # Collect filters and sorting parameters from the request
    filters = {
        "min_price": request.args.get("min_price"),
        "max_price": request.args.get("max_price"),
        "min_discounted_price": request.args.get("min_discounted_price"),
        "max_discounted_price": request.args.get("max_discounted_price"),
        "min_discount": request.args.get("min_discount"),
        "max_discount": request.args.get("max_discount"),
        "team_id": request.args.get("team_id"),
        "category": request.args.get("category"),
        "sort_by": request.args.get("sort_by", "Name"),
        "order": request.args.get("order", "asc"),
    }
    
    # Remove None values from filters to avoid sending unnecessary query params
    filters = {k: v for k, v in filters.items() if v is not None}

    # Fetch products from backend with filters applied
    response = requests.get(f"{BACKEND_URL}/products", headers=headers, params=filters)
    products = response.json() if response.status_code == 200 else []

    return render_template("product_manager.html", products=products)


@app.route('/product/add', methods=['GET', 'POST'])
def add_product():
    token = session.get("token")  # Retrieve the token from the session
    if token is None:
        flash("You need to log in first.", "danger")
        return redirect("/login")
    # Use the token to make an authenticated request
    headers = {"Authorization": f"Bearer {token}"}

    if "Product Manager" not in session.get("roles", []):
        flash("Access denied.", "danger")
        return redirect("/menu")

    form = ProductForm()

    if form.validate_on_submit():
        # Prepare the form data for submission
        data = {
            "name": form.name.data,
            "team_id": form.team_id.data,
            "category": form.category.data,
            "price": form.price.data,
            "discount": form.discount.data,
            "description": form.description.data,
        }

        # Prepare the file for upload
        files = {
            'image': form.image.data  # Handle file upload as a 'file' field
        }

        # Send the POST request with the form data and file
        response = requests.post(f"{BACKEND_URL}/products", headers=headers, data=data, files=files)
        if response.status_code == 201:
            flash("Product added successfully!", "success")
            return redirect(url_for('product_management_page'))
        else:
            flash(f"Error: {response.json().get('error', 'Failed to add product')}", "danger")

    return render_template("add_product.html", form=form)

@app.route('/product/edit/<int:id>', methods=['GET', 'POST'])
def edit_product(id):
    token = session.get("token")  # Retrieve the token from the session
    if token is None:
        flash("You need to log in first.", "danger")
        return redirect("/login")

    headers = {"Authorization": f"Bearer {token}"}

    if "Product Manager" not in session.get("roles", []):
        flash("Access denied.", "danger")
        return redirect("/menu")

    # Fetch the product details from the backend
    response = requests.get(f"{BACKEND_URL}/products/{id}", headers=headers)

    if response.status_code != 200:
        flash("Failed to fetch product details.", "danger")
        return redirect(url_for('product_management_page'))

    product = response.json()
    # Pre-fill the form with the product data
    form = ProductForm(data=product)

    if form.validate_on_submit():
        # Prepare the data for updating, excluding files initially
        data = {
            "name": form.name.data,
            "team_id": form.team_id.data,
            "category": form.category.data,
            "price": form.price.data,
            "discount": form.discount.data,
            "description": form.description.data,
        }

        # Handle file upload
        files = {"image": form.image.data} if form.image.data else None

        # Send the update request
        update_response = requests.put(
            f"{BACKEND_URL}/update-products/{id}",
            headers=headers,
            data=data,
            files=files,
        )

        if update_response.status_code == 200:
            flash("Product updated successfully!", "success")
            return redirect(url_for('product_management_page'))
        else:
            flash(f"Error: {update_response.json().get('error', 'Failed to update product')}", "danger")

    return render_template("edit_product.html", form=form, product=product)



@app.route('/product/delete/<int:id>', methods=['POST'])
def delete_product(id):
    token = session.get("token")  # Retrieve the token from the session
    if token is None:
        flash("You need to log in first.", "danger")
        return redirect("/login")
    # Use the token to make an authenticated request
    headers = {"Authorization": f"Bearer {token}"}

    if "Product Manager" not in session.get("roles", []):
        flash("Access denied.", "danger")
        return redirect("/menu")

    response = requests.delete(f"{BACKEND_URL}/delete-products/{id}", headers=headers)
    if response.status_code == 200:
        flash("Product deleted successfully!", "success")
    else:
        flash("Failed to delete product!", "danger")
    return redirect(url_for('product_management_page'))


@app.route('/product/upload_csv', methods=['GET', 'POST'])
def upload_csv():
    token = session.get("token")  # Retrieve the token from the session
    if token is None:
        flash("You need to log in first.", "danger")
        return redirect("/login")
    # Use the token to make an authenticated request
    headers = {"Authorization": f"Bearer {token}"}

    if "Product Manager" not in session.get("roles", []):
        flash("Access denied.", "danger")
        return redirect("/menu")

    if request.method == 'POST':
        file = request.files['file']
        files = {"file": (file.filename, file.stream, file.mimetype)}
        response = requests.post(f"{BACKEND_URL}/product_bulk_upload_csv", files=files, headers=headers )

        if response.status_code == 201:
            flash("Products uploaded successfully from CSV!", "success")
        else:
            error_message = response.json().get('error', 'Failed to upload CSV')
            flash(f"Error: {error_message}", "danger")

        return redirect(url_for('product_management_page'))

    return render_template("upload_csv.html")


if __name__ == '__main__':
    app.run(debug=True, port=5000)
