import os
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
db = SQLAlchemy(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Encryption Key Setup
KEY_FILE = "secret.key"


def get_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            return file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
        return key


key = get_encryption_key()
cipher_suite = Fernet(key)


def encrypt_password(password):
    return cipher_suite.encrypt(password.encode()).decode()


def decrypt_password(encrypted_password):
    try:
        return cipher_suite.decrypt(encrypted_password.encode()).decode()
    except Exception:
        return "**Decryption Error**"


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    website = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 🔹 NEW: Link to User Table



with app.app_context():
    db.create_all()


# Force login before accessing any page
@app.before_request
def require_login():
    allowed_routes = ['login', 'register', 'static']
    if "user_id" not in session and request.endpoint not in allowed_routes:
        return redirect(url_for('login'))


# Redirect root URL to login
@app.route('/')
def home():
    return redirect(url_for('login'))


# Dashboard (Requires Login)
@app.route('/dashboard')
def index():
    if "user_id" not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    passwords = Password.query.filter_by(user_id=user.id).all()  # ✅ Filter by user_id

    return render_template('index.html', passwords=passwords, user=user, decrypt_password=decrypt_password)


@app.route('/search')
def search():
    if "user_id" not in session:
        return jsonify([])  # Ensure user is logged in

    query = request.args.get('query', '').lower()
    user_id = session['user_id']  # Get logged-in user ID

    if query:
        results = Password.query.filter(
            (Password.website.ilike(f'%{query}%')) | (Password.username.ilike(f'%{query}%')),
            Password.user_id == user_id  # ✅ Only return passwords of the logged-in user
        ).all()

        search_results = [
            {
                'website': result.website,
                'username': result.username,
                'id': result.id
            }
            for result in results
        ]
        return jsonify(search_results)

    return jsonify([])  # Return an empty list if no query



@app.route('/add', methods=['GET', 'POST'])
def add_password():
    if "user_id" not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = encrypt_password(request.form['password'])
        notes = request.form.get('notes', '')

        new_entry = Password(
            website=website,
            username=username,
            password=password,
            notes=notes,
            user_id=session['user_id']  # ✅ Assign to logged-in user
        )

        db.session.add(new_entry)
        db.session.commit()
        flash("Password added successfully!", "success")
        return redirect(url_for('index'))

    return render_template('add.html')



# Update Existing Password
@app.route('/update/<int:id>', methods=['GET', 'POST'])
def update_password(id):
    password = Password.query.get_or_404(id)
    if request.method == 'POST':
        password.website = request.form['website']
        password.username = request.form['username']
        password.password = encrypt_password(request.form['password'])
        password.notes = request.form.get('notes', '')
        db.session.commit()
        return redirect(url_for('index'))

    decrypted_password = decrypt_password(password.password)
    return render_template('update.html', password=password, decrypted_password=decrypted_password)


# Export Data (CSV & Excel)
@app.route('/export/<file_type>')
def export(file_type):
    if "user_id" not in session:
        return redirect(url_for('login'))

    passwords = Password.query.all()
    data = [{
        'Website': p.website,
        'Username': p.username,
        'Password': decrypt_password(p.password),
        'Date Created': p.date_created.strftime('%Y-%m-%d'),
        'Last Updated': p.date_updated.strftime('%Y-%m-%d'),
        'Notes': p.notes
    } for p in passwords]

    df = pd.DataFrame(data)
    file_path = f"exported_passwords.{file_type}"

    if file_type == "csv":
        df.to_csv(file_path, index=False)
    elif file_type in ["xls", "xlsx"]:
        df.to_excel(file_path, index=False)

    return send_file(file_path, as_attachment=True)


# Import Data (CSV & Excel)
@app.route('/import', methods=['POST'])
def import_file():
    if "user_id" not in session:
        return redirect(url_for('login'))

    if 'file' not in request.files:
        flash('No file selected!', 'error')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected!', 'error')
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(file_path)
        elif filename.endswith((".xls", ".xlsx")):
            df = pd.read_excel(file_path)
        else:
            flash('Invalid file type! Only CSV and Excel files are allowed.', 'error')
            return redirect(url_for('index'))

        for _, row in df.iterrows():
            new_entry = Password(
                website=row['Website'],
                username=row['Username'],
                password=encrypt_password(row['Password']),
                notes=row.get('Notes', ''),
                user_id=session['user_id']  # ✅ Assign to logged-in user
            )
            db.session.add(new_entry)

        db.session.commit()
        flash('Passwords imported successfully!', 'success')

    except Exception as e:
        flash(f"Error importing file: {str(e)}", 'error')

    return redirect(url_for('index'))


# Register New User
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            return render_template("register.html", error="User already exists")

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# Login User
@app.route('/login', methods=['GET', 'POST'])
def login():
    if "user_id" in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash("Login successful!", "success")
            return redirect(url_for('index'))

        return render_template("login.html", error="Invalid username or password")

    return render_template('login.html')


# Logout User
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


# Delete Password Entry
@app.route('/delete/<int:id>')
def delete_password(id):
    password = Password.query.get_or_404(id)
    db.session.delete(password)
    db.session.commit()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
