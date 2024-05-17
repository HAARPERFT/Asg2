import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Create users table
def create_table():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    recovery_code TEXT
                )''')
    conn.commit()
    conn.close()

create_table()

# Function to generate a random recovery code
def generate_recovery_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT password FROM users WHERE username = ?''', (username,))
        result = c.fetchone()
        conn.close()

        if result and check_password_hash(result[0], password):
            # Authentication successful
            session['username'] = username
            return redirect(url_for('homepage'))
        else:
            # Authentication failed
            return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check password complexity
        if not re.match(r"^(?=.*[A-Z])(?=.*[!@#$%^&*])(?=.{8,})[a-zA-Z0-9!@#$%^&*]+$", password):
            return "Password must contain at least 1 uppercase letter, 1 special character, and be at least 8 characters long."

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Check if username already exists
        c.execute('''SELECT COUNT(*) FROM users WHERE username = ?''', (username,))
        count = c.fetchone()[0]
        
        if count > 0:
            conn.close()
            return "Username already exists. Please choose a different username."
        
        # Insert new user if username is unique
        c.execute('''INSERT INTO users (username, password) VALUES (?, ?)''', (username, hashed_password))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/password_recovery', methods=['GET', 'POST'])
def password_recovery():
    if request.method == 'POST':
        username = request.form['username']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT username FROM users WHERE username = ?''', (username,))
        result = c.fetchone()
        if result:
            recovery_code = generate_recovery_code()
            c.execute('''UPDATE users SET recovery_code = ? WHERE username = ?''', (recovery_code, username))
            conn.commit()
            conn.close()
            # In a real application, you would send the recovery code to the user's email or phone
            return "Recovery code sent successfully. Check your email or phone."
        else:
            conn.close()
            return "Username not found. Please try again."

    try:
        return render_template('password_recovery.html')
    except Exception as e:
        print("Error rendering password_recovery.html:", e)
        return "Error rendering password recovery page. Please try again later."

@app.route('/order_pizza', methods=['GET', 'POST'])
def order_pizza():
    if request.method == 'POST':
        pizza_types = request.form.getlist('pizza_type[]')
        quantities = request.form.getlist('quantity[]')

        # Define pizza prices
        pizza_prices = {
            "Margherita": 8.50,
            "Pepperoni": 9.00,
            "Hawaiian": 10.00,
            "Veggie": 9.50
        }

        total_price = sum(pizza_prices[pizza] * int(quantity) for pizza, quantity in zip(pizza_types, quantities))

        return render_template('order_confirmation.html', pizza_types=pizza_types, quantities=quantities, total_price=total_price)

    return render_template('order_pizza.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

# Homepage route
@app.route('/')
def homepage():
    return render_template('homepage.html')

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
