from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///groceries.db'
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    items = db.relationship('GroceryItem', backref='user', lazy=True)

class GroceryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Login required decorator
def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate username and password
        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('signup'))
            
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return redirect(url_for('signup'))
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return redirect(url_for('signup'))
        
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists. Please choose another one.', 'error')
            return redirect(url_for('signup'))
        
        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'error')
            return redirect(url_for('signup'))
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Username not found. Please check your username or sign up.', 'error')
            return redirect(url_for('login'))
            
        if not check_password_hash(user.password, password):
            flash('Incorrect password. Please try again.', 'error')
            return redirect(url_for('login'))
            
        session['user_id'] = user.id
        flash(f'Welcome back, {username}!', 'success')
        return redirect(url_for('index'))
        
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        username = user.username if user else 'User'
        session.pop('user_id', None)
        flash(f'Goodbye {username}! You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    user_id = session.get('user_id')
    items = GroceryItem.query.filter_by(user_id=user_id).order_by(GroceryItem.date_added).all()
    return render_template('index.html', items=items)

@app.route('/add', methods=['POST'])
@login_required
def add():
    name = request.form['name']
    quantity = request.form['quantity']
    user_id = session.get('user_id')
    new_item = GroceryItem(name=name, quantity=quantity, user_id=user_id)
    db.session.add(new_item)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/complete/<int:id>')
@login_required
def complete(id):
    item = GroceryItem.query.get_or_404(id)
    item.completed = not item.completed
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    item = GroceryItem.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
