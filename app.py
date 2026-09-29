import os
import sqlite3
import datetime
from functools import wraps
from flask import (
    Flask, render_template_string, request, redirect, 
    url_for, flash, session, g, send_file, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- CONFIGURATION & SECURITY ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-dev-secret-key-change-in-prod')
app.config['DATABASE'] = os.path.join(app.root_path, 'pos_database.db')
app.config['ENV'] = os.environ.get('APP_ENV', 'development')

if app.config['ENV'] == 'production' and app.config['SECRET_KEY'] == 'default-dev-secret-key-change-in-prod':
    raise RuntimeError("Production builds require a custom SECRET_KEY set in environment variables.")

# --- DATABASE SETUP & MIGRATION ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON;")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()
    
    # Store Profile
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS store_profile (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            address TEXT,
            phone TEXT
        );
    ''')
    
    # Insert default store if empty
    cursor.execute("SELECT COUNT(*) FROM store_profile")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO store_profile (id, name, address, phone) VALUES (1, 'My Tech Shop', '123 Main Street', '9876543210')")

    # Users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'admin'
        );
    ''')
    
    # Create default admin if empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        bootstrap_pass = os.environ.get('BOOTSTRAP_ADMIN_PASSWORD', 'AdminPass12345!')
        hashed = generate_password_hash(bootstrap_pass)
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', ?, 'admin')", (hashed,))

    # Categories
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
    ''')

    # Products
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category_id INTEGER,
            cost_price REAL NOT NULL,
            selling_price REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (category_id) REFERENCES categories (id)
        );
    ''')

    # Customers
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT UNIQUE,
            credit_due REAL DEFAULT 0.0
        );
    ''')

    # Sales History
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_amount REAL NOT NULL,
            total_cost REAL NOT NULL,
            payment_method TEXT NOT NULL,
            customer_id INTEGER,
            FOREIGN KEY (customer_id) REFERENCES customers (id)
        );
    ''')

    # Sale Items
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            unit_cost REAL NOT NULL,
            FOREIGN KEY (sale_id) REFERENCES sales (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        );
    ''')

    db.commit()

@app.cli.command('init-db')
def init_db_command():
    init_db()
    print("Database initialized successfully.")

# --- HELPERS & SECURITY ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# CSRF Protection Mock/Check
@app.before_request
def generate_csrf():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(16).hex()

def verify_csrf():
    token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    if not token or token != session.get('csrf_token'):
        flash("Invalid security token (CSRF). Try again.", "danger")
        return False
    return True

# --- HTML TEMPLATES (SINGLE-FILE EMBEDDED) ---
LAYOUT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>POS System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .low-stock { background-color: #f8d7da !important; color: #842029; font-weight: bold; }
        .sidebar { min-height: 100vh; background-color: #212529; color: white; }
        .sidebar a { color: #cfd8dc; text-decoration: none; padding: 10px 15px; display: block; }
        .sidebar a:hover, .sidebar a.active { background-color: #0d6efd; color: white; }
    </style>
</head>
<body>
<div class="container-fluid">
    <div class="row">
        {% if session.get('user_id') %}
        <div class="col-md-2 sidebar p-0">
            <h4 class="text-center py-3 border-bottom">POS System</h4>
            <a href="{{ url_for('dashboard') }}">🛒 POS / Checkout</a>
            <a href="{{ url_for('products') }}">📦 Products & Stock</a>
            <a href="{{ url_for('categories') }}">🏷️ Categories</a>
            <a href="{{ url_for('customers') }}">👥 Customers & Kadhan</a>
            <a href="{{ url_for('reports') }}">📊 Sales & Profit/Loss</a>
            <a href="{{ url_for('settings') }}">⚙️ Settings & Backup</a>
            <a href="{{ url_for('logout') }}" class="text-danger mt-4">🚪 Logout</a>
        </div>
        <div class="col-md-10 p-4">
        {% else %}
        <div class="col-12 p-4">
        {% endif %}
            
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                {% for category, message in messages %}
                  <div class="alert alert-{{ category }} alert-dismissible fade show">{{ message }}</div>
                {% endfor %}
              {% endif %}
            {% endwith %}

            {% block content %}{% endblock %}
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid Username or Password", "danger")

    return render_template_string(LAYOUT_TEMPLATE + """
    {% block content %}
    <div class="row justify-content-center mt-5">
        <div class="col-md-4">
            <div class="card shadow">
                <div class="card-header bg-primary text-white text-center"><h4>Store Login</h4></div>
                <div class="card-body">
                    <form method="POST">
                        <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                        <div class="mb-3">
                            <label>Username</label>
                            <input type="text" name="username" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label>Password</label>
                            <input type="password" name="password" class="form-control" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    db = get_db()
    products = db.execute("SELECT * FROM products WHERE stock > 0").fetchall()
    customers = db.execute("SELECT * FROM customers").fetchall()
    return render_template_string(LAYOUT_TEMPLATE + """
    {% block content %}
    <h2>POS / Billing Counter</h2>
    <div class="row mt-3">
        <div class="col-md-7">
            <h4>Available Products</h4>
            <table class="table table-bordered align-middle">
                <thead>
                    <tr><th>Product</th><th>Price</th><th>Stock</th><th>Action</th></tr>
                </thead>
                <tbody>
                    {% for p in products %}
                    <tr class="{{ 'low-stock' if p.stock <= 5 else '' }}">
                        <td>{{ p.name }}</td>
                        <td>₹{{ "%.2f"|format(p.selling_price) }}</td>
                        <td>{{ p.stock }}</td>
                        <td>
                            <form method="POST" action="{{ url_for('add_to_cart') }}" class="d-flex">
                                <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                                <input type="hidden" name="product_id" value="{{ p.id }}">
                                <input type="number" name="quantity" value="1" min="1" max="{{ p.stock }}" class="form-control form-control-sm me-2" style="width:70px;">
                                <button type="submit" class="btn btn-sm btn-success">Add</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="col-md-5">
            <div class="card shadow">
                <div class="card-header bg-dark text-white">Current Cart</div>
                <div class="card-body">
                    {% set cart = session.get('cart', {}) %}
                    {% if cart %}
                    <table class="table table-sm">
                        <thead><tr><th>Item</th><th>Qty</th><th>Subtotal</th></tr></thead>
                        <tbody>
                            {% set total = namespace(val=0) %}
                            {% for item_id, item in cart.items() %}
                            {% set sub = item.price * item.quantity %}
                            {% set total.val = total.val + sub %}
                            <tr>
                                <td>{{ item.name }}</td>
                                <td>{{ item.quantity }}</td>
                                <td>₹{{ "%.2f"|format(sub) }}</td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                    <h4 class="text-end text-primary">Total: ₹{{ "%.2f"|format(total.val) }}</h4>
                    <hr>
                    <form method="POST" action="{{ url_for('checkout') }}">
                        <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                        <div class="mb-2">
                            <label>Customer (Optional / Kadhan):</label>
                            <select name="customer_id" class="form-select">
                                <option value="">-- Cash Customer --</option>
                                {% for c in customers %}
                                <option value="{{ c.id }}">{{ c.name }} (Due: ₹{{ "%.2f"|format(c.credit_due) }})</option>
                                {% endfor %}
                            </select>
                        </div>
                        <div class="mb-3">
                            <label>Payment Method:</label>
                            <select name="payment_method" class="form-select" required>
                                <option value="Cash">Cash</option>
                                <option value="Card">Card</option>
                                <option value="UPI/Online">UPI / Online</option>
                                <option value="Credit">Credit (Kadhan)</option>
                            </select>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Complete Sale & Print Receipt</button>
                    </form>
                    {% else %}
                    <p class="text-muted">Cart is empty.</p>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>
    {% endblock %}
    """, products=products, customers=customers)

@app.route('/cart/add', methods=['POST'])
@login_required
def add_to_cart():
    if not verify_csrf(): return redirect(url_for('dashboard'))
    product_id = request.form.get('product_id')
    quantity = int(request.form.get('quantity', 1))

    db = get_db()
    product = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()

    if not product or product['stock'] < quantity:
        flash("Not enough stock available!", "danger")
        return redirect(url_for('dashboard'))

    cart = session.get('cart', {})
    if str(product_id) in cart:
        cart[str(product_id)]['quantity'] += quantity
    else:
        cart[str(product_id)] = {
            'name': product['name'],
            'price': product['selling_price'],
            'cost': product['cost_price'],
            'quantity': quantity
        }
    session['cart'] = cart
    flash("Added to cart.", "info")
    return redirect(url_for('dashboard'))

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    if not verify_csrf(): return redirect(url_for('dashboard'))
    cart = session.get('cart', {})
    if not cart:
        flash("Cart is empty!", "warning")
        return redirect(url_for('dashboard'))

    payment_method = request.form.get('payment_method')
    customer_id = request.form.get('customer_id')

    if payment_method == 'Credit' and not customer_id:
        flash("Please select a customer for Credit (Kadhan) payment!", "danger")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    try:
        # Atomic Transaction
        cursor.execute("BEGIN TRANSACTION;")
        
        total_amount = 0
        total_cost = 0

        # Validate Stock & Reload Prices from DB inside Transaction
        for p_id, item in cart.items():
            prod = cursor.execute("SELECT * FROM products WHERE id = ?", (p_id,)).fetchone()
            if not prod or prod['stock'] < item['quantity']:
                raise ValueError(f"Insufficient stock for {item['name']}")
            
            total_amount += prod['selling_price'] * item['quantity']
            total_cost += prod['cost_price'] * item['quantity']

            # Deduct Stock
            cursor.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (item['quantity'], p_id))

        # Record Sale
        cursor.execute('''
            INSERT INTO sales (total_amount, total_cost, payment_method, customer_id)
            VALUES (?, ?, ?, ?)
        ''', (total_amount, total_cost, payment_method, customer_id if customer_id else None))
        
        sale_id = cursor.lastrowid

        # Insert Sale Items
        for p_id, item in cart.items():
            prod = cursor.execute("SELECT * FROM products WHERE id = ?", (p_id,)).fetchone()
            cursor.execute('''
                INSERT INTO sale_items (sale_id, product_id, quantity, unit_price, unit_cost)
                VALUES (?, ?, ?, ?, ?)
            ''', (sale_id, p_id, item['quantity'], prod['selling_price'], prod['cost_price']))

        # Handle Kadhan (Credit)
        if payment_method == 'Credit' and customer_id:
            cursor.execute("UPDATE customers SET credit_due = credit_due + ? WHERE id = ?", (total_amount, customer_id))

        db.commit()
        session.pop('cart', None)
        flash("Transaction Successful!", "success")
        return redirect(url_for('receipt', sale_id=sale_id))

    except Exception as e:
        db.rollback()
        flash(f"Checkout Failed: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

@app.route('/receipt/<int:sale_id>')
@login_required
def receipt(sale_id):
    db = get_db()
    store = db.execute("SELECT * FROM store_profile WHERE id = 1").fetchone()
    sale = db.execute("SELECT sales.*, customers.name as cust_name FROM sales LEFT JOIN customers ON sales.customer_id = customers.id WHERE sales.id = ?", (sale_id,)).fetchone()
    items = db.execute("SELECT sale_items.*, products.name FROM sale_items JOIN products ON sale_items.product_id = products.id WHERE sale_id = ?", (sale_id,)).fetchall()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Receipt #{{ sale.id }}</title>
        <style>
            body { font-family: monospace; width: 300px; margin: auto; padding: 10px; }
            .center { text-align: center; }
            .flex { display: flex; justify-content: space-between; }
            hr { border-top: 1px dashed #000; }
        </style>
    </head>
    <body>
        <div class="center">
            <h3>{{ store.name }}</h3>
            <p>{{ store.address }}<br>Phone: {{ store.phone }}</p>
        </div>
        <hr>
        <p>Receipt #: {{ sale.id }}<br>Date: {{ sale.timestamp }}<br>Customer: {{ sale.cust_name or 'Cash' }}</p>
        <hr>
        {% for i in items %}
        <div class="flex">
            <span>{{ i.name }} x{{ i.quantity }}</span>
            <span>₹{{ "%.2f"|format(i.unit_price * i.quantity) }}</span>
        </div>
        {% endfor %}
        <hr>
        <div class="flex"><strong>Total:</strong><strong>₹{{ "%.2f"|format(sale.total_amount) }}</strong></div>
        <div class="flex"><span>Payment:</span><span>{{ sale.payment_method }}</span></div>
        <hr>
        <p class="center">Thank you! Visit again.</p>
        <div class="center"><button onclick="window.print()">Print Receipt</button></div>
    </body>
    </html>
    """, store=store, sale=sale, items=items)

# --- PRODUCTS & CATEGORIES ---

@app.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    db = get_db()
    if request.method == 'POST':
        if not verify_csrf(): return redirect(url_for('products'))
        name = request.form.get('name')
        category_id = request.form.get('category_id')
        cost_price = float(request.form.get('cost_price'))
        selling_price = float(request.form.get('selling_price'))
        stock = int(request.form.get('stock'))

        db.execute("INSERT INTO products (name, category_id, cost_price, selling_price, stock) VALUES (?, ?, ?, ?, ?)",
                   (name, category_id, cost_price, selling_price, stock))
        db.commit()
        flash("Product added successfully!", "success")
        return redirect(url_for('products'))

    products = db.execute("SELECT products.*, categories.name as category_name FROM products LEFT JOIN categories ON products.category_id = categories.id").fetchall()
    categories = db.execute("SELECT * FROM categories").fetchall()
    return render_template_string(LAYOUT_TEMPLATE + """
    {% block content %}
    <h2>Product & Inventory Management</h2>
    <div class="row">
        <div class="col-md-4">
            <div class="card p-3">
                <h5>Add New Product</h5>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                    <div class="mb-2"><label>Name</label><input type="text" name="name" class="form-control" required></div>
                    <div class="mb-2"><label>Category</label>
                        <select name="category_id" class="form-select">
                            {% for c in categories %}<option value="{{ c.id }}">{{ c.name }}</option>{% endfor %}
                        </select>
                    </div>
                    <div class="mb-2"><label>Cost Price</label><input type="number" step="0.01" name="cost_price" class="form-control" required></div>
                    <div class="mb-2"><label>Selling Price</label><input type="number" step="0.01" name="selling_price" class="form-control" required></div>
                    <div class="mb-2"><label>Initial Stock</label><input type="number" name="stock" class="form-control" required></div>
                    <button type="submit" class="btn btn-primary w-100">Save Product</button>
                </form>
            </div>
        </div>
        <div class="col-md-8">
            <table class="table table-bordered">
                <thead><tr><th>Name</th><th>Category</th><th>Cost</th><th>Price</th><th>Stock</th></tr></thead>
                <tbody>
                    {% for p in products %}
                    <tr class="{{ 'low-stock' if p.stock <= 5 else '' }}">
                        <td>{{ p.name }}</td><td>{{ p.category_name }}</td>
                        <td>₹{{ p.cost_price }}</td><td>₹{{ p.selling_price }}</td>
                        <td>{{ p.stock }} {% if p.stock <= 5 %}<span class="badge bg-danger">Low Stock</span>{% endif %}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    {% endblock %}
    """, products=products, categories=categories)

@app.route('/categories', methods=['GET', 'POST'])
@login_required
def categories():
    db = get_db()
    if request.method == 'POST':
        if not verify_csrf(): return redirect(url_for('categories'))
        name = request.form.get('name')
        try:
            db.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            db.commit()
            flash("Category created!", "success")
        except sqlite3.IntegrityError:
            flash("Category already exists!", "danger")
        return redirect(url_for('categories'))

    categories = db.execute("SELECT * FROM categories").fetchall()
    return render_template_string(LAYOUT_TEMPLATE + """
    {% block content %}
    <h2>Category Management</h2>
    <div class="row">
        <div class="col-md-4">
            <form method="POST" class="card p-3">
                <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                <div class="mb-2"><label>Category Name</label><input type="text" name="name" class="form-control" required></div>
                <button type="submit" class="btn btn-primary">Add Category</button>
            </form>
        </div>
        <div class="col-md-8">
            <ul class="list-group">
                {% for c in categories %}
                <li class="list-group-item">{{ c.name }}</li>
                {% endfor %}
            </ul>
        </div>
    </div>
    {% endblock %}
    """, categories=categories)

# --- CUSTOMERS & KADHAN (CREDIT) ---

@app.route('/customers', methods=['GET', 'POST'])
@login_required
def customers():
    db = get_db()
    if request.method == 'POST':
        if not verify_csrf(): return redirect(url_for('customers'))
        name = request.form.get('name')
        phone = request.form.get('phone')
        db.execute("INSERT INTO customers (name, phone) VALUES (?, ?)", (name, phone))
        db.commit()
        flash("Customer added!", "success")
        return redirect(url_for('customers'))

    customers = db.execute("SELECT * FROM customers").fetchall()
    return render_template_string(LAYOUT_TEMPLATE + """
    {% block content %}
    <h2>Customer & Credit (Kadhan) Tracking</h2>
    <div class="row">
        <div class="col-md-4">
            <form method="POST" class="card p-3">
                <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                <div class="mb-2"><label>Customer Name</label><input type="text" name="name" class="form-control" required></div>
                <div class="mb-2"><label>Phone</label><input type="text" name="phone" class="form-control"></div>
                <button type="submit" class="btn btn-primary">Add Customer</button>
            </form>
        </div>
        <div class="col-md-8">
            <table class="table table-bordered">
                <thead><tr><th>Name</th><th>Phone</th><th>Outstanding Credit Due</th><th>Action</th></tr></thead>
                <tbody>
                    {% for c in customers %}
                    <tr>
                        <td>{{ c.name }}</td><td>{{ c.phone }}</td>
                        <td class="text-danger fw-bold">₹{{ "%.2f"|format(c.credit_due) }}</td>
                        <td>
                            {% if c.credit_due > 0 %}
                            <form method="POST" action="{{ url_for('settle_credit', customer_id=c.id) }}">
                                <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                                <button type="submit" class="btn btn-sm btn-success">Settle Due</button>
                            </form>
                            {% else %}<span class="text-muted">Clear</span>{% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
    {% endblock %}
    """, customers=customers)

@app.route('/customers/settle/<int:customer_id>', methods=['POST'])
@login_required
def settle_credit(customer_id):
    if not verify_csrf(): return redirect(url_for('customers'))
    db = get_db()
    db.execute("UPDATE customers SET credit_due = 0 WHERE id = ?", (customer_id,))
    db.commit()
    flash("Customer credit settled completely!", "success")
    return redirect(url_for('customers'))

# --- REPORTS & PROFIT/LOSS ---

@app.route('/reports')
@login_required
def reports():
    db = get_db()
    sales = db.execute("SELECT sales.*, customers.name as cust_name FROM sales LEFT JOIN customers ON sales.customer_id = customers.id ORDER BY timestamp DESC").fetchall()
    
    total_revenue = sum(s['total_amount'] for s in sales)
    total_cost = sum(s['total_cost'] for s in sales)
    net_profit = total_revenue - total_cost

    return render_template_string(LAYOUT_TEMPLATE + """
    {% block content %}
    <h2>Sales History & Profit / Loss Report</h2>
    <div class="row my-3">
        <div class="col-md-4"><div class="card p-3 bg-primary text-white"><h5>Total Revenue</h5><h3>₹{{ "%.2f"|format(total_revenue) }}</h3></div></div>
        <div class="col-md-4"><div class="card p-3 bg-secondary text-white"><h5>Total Cost of Goods</h5><h3>₹{{ "%.2f"|format(total_cost) }}</h3></div></div>
        <div class="col-md-4"><div class="card p-3 {{ 'bg-success' if net_profit >= 0 else 'bg-danger' }} text-white"><h5>Net Profit / Loss</h5><h3>₹{{ "%.2f"|format(net_profit) }}</h3></div></div>
    </div>

    <h4>Recent Transactions</h4>
    <table class="table table-striped">
        <thead><tr><th>Sale ID</th><th>Date</th><th>Customer</th><th>Method</th><th>Total</th><th>Cost</th><th>Profit</th><th>Action</th></tr></thead>
        <tbody>
            {% for s in sales %}
            <tr>
                <td>#{{ s.id }}</td><td>{{ s.timestamp }}</td><td>{{ s.cust_name or 'Cash' }}</td>
                <td>{{ s.payment_method }}</td><td>₹{{ s.total_amount }}</td><td>₹{{ s.total_cost }}</td>
                <td class="text-success fw-bold">₹{{ "%.2f"|format(s.total_amount - s.total_cost) }}</td>
                <td><a href="{{ url_for('receipt', sale_id=s.id) }}" target="_blank" class="btn btn-sm btn-outline-dark">Receipt</a></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endblock %}
    """, sales=sales, total_revenue=total_revenue, total_cost=total_cost, net_profit=net_profit)

# --- STORE PROFILE & 1-CLICK BACKUP ---

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    db = get_db()
    if request.method == 'POST':
        if not verify_csrf(): return redirect(url_for('settings'))
        name = request.form.get('name')
        address = request.form.get('address')
        phone = request.form.get('phone')
        
        db.execute("UPDATE store_profile SET name = ?, address = ?, phone = ? WHERE id = 1", (name, address, phone))
        db.commit()
        flash("Store profile updated!", "success")
        return redirect(url_for('settings'))

    store = db.execute("SELECT * FROM store_profile WHERE id = 1").fetchone()
    return render_template_string(LAYOUT_TEMPLATE + """
    {% block content %}
    <h2>Store Profile & Backup Settings</h2>
    <div class="row">
        <div class="col-md-6">
            <div class="card p-3">
                <h5>Store Information</h5>
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                    <div class="mb-2"><label>Store Name</label><input type="text" name="name" value="{{ store.name }}" class="form-control" required></div>
                    <div class="mb-2"><label>Address</label><input type="text" name="address" value="{{ store.address }}" class="form-control"></div>
                    <div class="mb-2"><label>Phone</label><input type="text" name="phone" value="{{ store.phone }}" class="form-control"></div>
                    <button type="submit" class="btn btn-primary">Update Profile</button>
                </form>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card p-3">
                <h5>1-Click Data Backup & Restore</h5>
                <p>Download your complete SQLite Database file for safe storage.</p>
                <a href="{{ url_for('backup_db') }}" class="btn btn-success mb-3">📥 Download Backup (.db)</a>
                <hr>
                <form method="POST" action="{{ url_for('restore_db') }}" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
                    <label class="form-label">Restore Database File</label>
                    <input type="file" name="backup_file" class="form-control mb-2" required>
                    <button type="submit" class="btn btn-danger">Upload & Restore</button>
                </form>
            </div>
        </div>
    </div>
    {% endblock %}
    """, store=store)

@app.route('/backup')
@login_required
def backup_db():
    return send_file(app.config['DATABASE'], as_attachment=True, download_name='pos_backup.db')

@app.route('/restore', methods=['POST'])
@login_required
def restore_db():
    if not verify_csrf(): return redirect(url_for('settings'))
    file = request.files.get('backup_file')
    if file and file.filename.endswith('.db'):
        file.save(app.config['DATABASE'])
        flash("Database restored successfully!", "success")
    else:
        flash("Invalid file format. Please upload a .db file.", "danger")
    return redirect(url_for('settings'))

# --- MAIN RUNNER ---
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
