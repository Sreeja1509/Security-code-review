# Secure Coding Review: Flask Web Application

## Sample Application

Let's consider a simple Flask application that allows users to register, login, and view a dashboard. Here's a basic version of such an application:

```python
from flask import Flask, request, render_template, redirect, session
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'very-secret-key'

def get_db():
    db = sqlite3.connect('users.db')
    db.execute('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)')
    return db

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        db = get_db()
        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password)).fetchone()
        if user:
            session['username'] = username
            return redirect('/dashboard')
        else:
            return 'Invalid credentials'
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return f'Welcome to your dashboard, {session["username"]}!'
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
```

## Static Code Analysis

We'll use Bandit for static code analysis. To set it up:

1. Install Bandit:
   ```
   pip install bandit
   ```

2. Run Bandit on our Flask application:
   ```
   bandit app.py
   ```

### Bandit Results

Bandit identifies several issues:

1. **B105**: Possible hardcoded password: 'very-secret-key'
2. **B303**: Use of insecure MD5 hash function
3. **B201**: Flask app appears to be run with debug=True, which exposes the Werkzeug debugger
4. **B608**: Possible SQL injection vector through string-based query construction

## Manual Code Review

Let's manually review our code for potential security issues:

### Security Vulnerabilities

1. **Insecure Secret Key**: The application uses a hardcoded, easily guessable secret key.

2. **Weak Password Hashing**: MD5 is a cryptographically broken hash function and should not be used for password hashing.

3. **SQL Injection**: The application constructs SQL queries using string formatting, which is vulnerable to SQL injection attacks.

4. **Lack of Input Validation**: There's no validation on user inputs, which could lead to various attacks.

5. **Session Management Issues**: The application uses Flask's default session management, which may not be suitable for production environments.

6. **Debug Mode in Production**: The application runs with debug=True, which should never be used in a production environment.

7. **Lack of CSRF Protection**: There's no protection against Cross-Site Request Forgery (CSRF) attacks.

8. **Insufficient Error Handling**: The application doesn't handle exceptions properly, which could lead to information disclosure.

9. **No Password Complexity Requirements**: The application doesn't enforce any password strength rules.

10. **Insecure Direct Object References**: The dashboard route doesn't check if the logged-in user has permission to access the requested data.

## Recommendations

1. **Secure Secret Key**: Use a strong, randomly generated key for app.secret_key. Store it in an environment variable, not in the code.

2. **Proper Password Hashing**: Use a secure password hashing algorithm like bcrypt, Argon2, or PBKDF2.

3. **Parameterized Queries**: Use parameterized queries or an ORM to prevent SQL injection.

4. **Input Validation**: Implement thorough input validation for all user inputs.

5. **Secure Session Management**: Consider using Flask-Session for server-side sessions.

6. **Production Configuration**: Ensure debug mode is turned off in production. Use environment variables to manage different configurations.

7. **CSRF Protection**: Implement CSRF protection, possibly using Flask-WTF.

8. **Error Handling**: Implement proper error handling and logging. Don't expose sensitive information in error messages.

9. **Password Policy**: Implement and enforce a strong password policy.

10. **Access Control**: Implement proper access control checks for all routes.

11. **HTTPS**: Ensure the application is served over HTTPS.

12. **Security Headers**: Implement security headers like Content Security Policy, X-Frame-Options, etc.

## Improved Code Example

Here's an example of how we could improve the security of our Flask application:

```python
from flask import Flask, request, render_template, redirect, session
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if len(password) < 8:
            return 'Password must be at least 8 characters long', 400
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect('/dashboard')
        else:
            return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])
    return f'Welcome to your dashboard, {user.username}!'

if __name__ == '__main__':
    db.create_all()
    app.run(debug=False)
```

This improved version addresses many of the security concerns identified in our review. Remember to update your `requirements.txt` file to include the new dependencies:

```
Flask==2.0.1
Flask-WTF==0.15.1
Flask-Bcrypt==0.7.1
Flask-SQLAlchemy==2.5.1
```

Always keep your dependencies up to date and regularly review your code for security issues.
