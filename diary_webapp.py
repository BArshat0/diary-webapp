from flask import Flask, request, redirect, url_for, render_template_string, send_from_directory, flash, jsonify, \
    session, abort, g
import os
import json
import re
import sqlite3
from datetime import datetime
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import secrets
import atexit
import logging
from logging.handlers import RotatingFileHandler

# --- Configuration ---
DIARY_DIR = 'diaries'
DATABASE = 'diary.db'

app = Flask(__name__)

# Production configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-dev-key-only')
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
# Setup logging
if not app.debug:
    if not os.path.exists('logs'):
        os.makedirs('logs')
    file_handler = RotatingFileHandler('logs/diary.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Diary application startup')

# Create necessary directories
os.makedirs(DIARY_DIR, exist_ok=True)

# --- Database Setup ---
def get_db():
    """Get database connection"""
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db():
    """Initialize database with required tables"""
    db = get_db()
    cursor = db.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')

    # Diaries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS diaries
        (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            filename TEXT UNIQUE NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')

    # Create indexes for better performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_diaries_user_id ON diaries(user_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_diaries_filename ON diaries(filename)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_diaries_updated_at ON diaries(updated_at)')

    db.commit()

@app.teardown_appcontext
def close_db(error):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Initialize database on startup
with app.app_context():
    init_db()

# --- Helper Functions ---
def validate_username(username):
    """Validate username format"""
    if not username or len(username) < 3 or len(username) > 20:
        return False
    # Only allow alphanumeric characters and underscores
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False
    return True

def validate_filename(filename):
    """Validate filename to prevent path traversal"""
    if not filename or len(filename) > 100:
        return False

    # Prevent path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        return False

    # More permissive pattern - allow letters, numbers, spaces, hyphens, underscores, dots
    if not re.match(r'^[a-zA-Z0-9_\-\.\s]+$', filename):
        return False

    return True

def sanitize_content(content):
    """Basic content sanitization to prevent XSS"""
    if len(content) > 1000000:  # 1MB max content size
        return None
    return content

def get_user_file_path(username, filename):
    """Safely get file path for a user's diary"""
    if not validate_username(username):
        return None

    if not validate_filename(filename):
        return None

    user_dir = get_user_dir(username)
    if not user_dir:
        return None

    file_path = os.path.join(user_dir, filename)

    # Normalize paths for comparison
    file_path = os.path.normpath(file_path)
    user_dir_norm = os.path.normpath(user_dir)

    # Check if file path is within user directory
    if not file_path.startswith(user_dir_norm):
        return None

    return file_path

def get_user_dir(username):
    if not validate_username(username):
        return None
    user_dir = os.path.join(DIARY_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def get_user_id(username):
    """Get user ID from username"""
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    return user['id'] if user else None

# --- CSRF Protection ---
# --- CSRF Protection ---
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
        app.logger.info(f"Generated new CSRF token: {session['csrf_token']}")
    return session['csrf_token']


def validate_csrf_token(token):
    stored_token = session.get('csrf_token')
    app.logger.info(f"CSRF Validation - Stored: {stored_token}, Received: {token}")

    if not token:
        app.logger.warning("No CSRF token provided")
        return False
    if not stored_token:
        app.logger.warning("No CSRF token in session")
        return False

    result = token and stored_token and secrets.compare_digest(token, stored_token)
    app.logger.info(f"CSRF Validation Result: {result}")
    return result
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Add this to debug session issues
# Debug session information (optional - you can remove this if not needed)
@app.before_request
def debug_session():
    app.logger.info(
        f"Session debug - User: {session.get('username')}, CSRF: {session.get('csrf_token')}")

# --- Login Required Decorator ---
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            flash('Please login first.', 'warning')
            return redirect(url_for('login'))

        # Verify the user still exists in database
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ?', (session['username'],))
        user = cursor.fetchone()

        if not user:
            session.pop('username', None)
            flash('Session expired. Please login again.', 'warning')
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return wrapper

# --- HTML TEMPLATES (Include your templates here) ---
LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login - Digital Diary</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&family=Playfair+Display:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #8a4fff;
      --primary-light: #a67cff;
      --primary-dark: #6b2dcc;
      --secondary: #ff6b9d;
      --accent: #4fd1c5;
      --dark: #1a1a2e;
      --light: #f8f9fa;
      --gradient: linear-gradient(135deg, var(--primary), var(--secondary));
    }
    * {
      box-sizing: border-box;
    }
    body {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Poppins', sans-serif;
      opacity: 0;
      transition: opacity 0.7s ease;
      padding: 1rem;
      position: relative;
      overflow-x: hidden;
    }
    body::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: url("data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11 18c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm48 25c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm-43-7c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm63 31c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM34 90c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm56-76c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM12 86c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm28-65c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm23-11c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-6 60c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm29 22c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zM32 63c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm57-13c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-9-21c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM60 91c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM35 41c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM12 60c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2z' fill='%23ffffff' fill-opacity='0.05' fill-rule='evenodd'/%3E%3C/svg%3E");
      opacity: 0.3;
    }
    .login-card {
      background: rgba(255, 255, 255, 0.95);
      backdrop-filter: blur(10px);
      border-radius: 20px;
      box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
      padding: 2.5rem;
      width: 100%;
      max-width: 420px;
      animation: fadeIn 0.8s ease;
      border: 1px solid rgba(255, 255, 255, 0.2);
      position: relative;
      overflow: hidden;
    }
    .login-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 5px;
      background: var(--gradient);
    }
    @keyframes fadeIn {
      from {opacity: 0; transform: translateY(20px);}
      to {opacity: 1; transform: translateY(0);}
    }
    .app-title {
      font-family: 'Playfair Display', serif;
      font-weight: 600;
      text-align: center;
      margin-bottom: 2rem;
      color: var(--dark);
      font-size: 2.2rem;
      position: relative;
      display: inline-block;
      width: 100%;
    }
    .app-title::after {
      content: '';
      position: absolute;
      bottom: -10px;
      left: 50%;
      transform: translateX(-50%);
      width: 60px;
      height: 3px;
      background: var(--gradient);
      border-radius: 3px;
    }
    .form-label {
      font-weight: 500;
      color: var(--dark);
      margin-bottom: 0.5rem;
    }
    .form-control {
      border-radius: 10px;
      padding: 0.75rem 1rem;
      border: 1px solid #e1e5e9;
      transition: all 0.3s ease;
      font-size: 1rem;
    }
    .form-control:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 0.25rem rgba(138, 79, 255, 0.25);
    }
    .btn-login {
      background: var(--gradient);
      border: none;
      border-radius: 10px;
      padding: 0.75rem;
      font-weight: 600;
      font-size: 1rem;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(138, 79, 255, 0.4);
    }
    .btn-login:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(138, 79, 255, 0.5);
    }
    .btn-signup {
      background: transparent;
      border: 2px solid var(--primary);
      border-radius: 10px;
      padding: 0.75rem;
      font-weight: 600;
      font-size: 1rem;
      transition: all 0.3s ease;
      color: var(--primary);
    }
    .btn-signup:hover {
      background: var(--primary);
      color: white;
      transform: translateY(-2px);
    }
    .toast {
      border-radius: 10px;
      border: none;
    }
    .floating-shapes {
      position: absolute;
      width: 100%;
      height: 100%;
      overflow: hidden;
      z-index: -1;
    }
    .shape {
      position: absolute;
      opacity: 0.1;
      border-radius: 50%;
    }
    .shape-1 {
      width: 300px;
      height: 300px;
      background: var(--primary);
      top: -150px;
      right: -150px;
    }
    .shape-2 {
      width: 200px;
      height: 200px;
      background: var(--secondary);
      bottom: -100px;
      left: -100px;
    }
    .auth-switch {
      text-align: center;
      margin-top: 1.5rem;
      padding-top: 1.5rem;
      border-top: 1px solid #e1e5e9;
    }
  </style>
</head>
<body>
  <div class="floating-shapes">
    <div class="shape shape-1"></div>
    <div class="shape shape-2"></div>
  </div>
  <div class="login-card">
    <h1 class="app-title">Digital Diary</h1>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <div class="mb-3">
        <label class="form-label">Username</label>
        <input type="text" name="username" class="form-control" required autofocus>
      </div>
      <div class="mb-4">
        <label class="form-label">Password</label>
        <input type="password" name="password" class="form-control" required>
      </div>
      <button class="btn btn-login w-100 text-white mb-3">Login</button>
    </form>

    <div class="auth-switch">
      <p class="text-muted mb-3">Don't have an account?</p>
      <a href="{{ url_for('signup') }}" class="btn btn-signup w-100">Create New Account</a>
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, msg in messages %}
        <div class="toast align-items-center text-bg-{{ category }} border-0 show mt-3" role="alert">
          <div class="d-flex">
            <div class="toast-body">{{ msg }}</div>
          </div>
        </div>
      {% endfor %}
    {% endwith %}
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      document.body.style.opacity = 0;
      setTimeout(() => document.body.style.opacity = 1, 50);

      const form = document.querySelector('form');
      form.addEventListener('submit', e => {
        e.preventDefault();
        document.body.style.transition = "opacity 0.7s ease, transform 0.7s ease";
        document.body.style.opacity = 0;
        document.body.style.transform = "translateX(-50px)";
        setTimeout(() => form.submit(), 700);
      });

      document.querySelector('.btn-signup').addEventListener('click', e => {
        e.preventDefault();
        const url = e.target.href;
        document.body.style.transition = "opacity 0.7s ease, transform 0.7s ease";
        document.body.style.opacity = 0;
        document.body.style.transform = "translateX(50px)";
        setTimeout(() => window.location.href = url, 700);
      });

      document.querySelectorAll('.toast').forEach(t => {
        const bsToast = new bootstrap.Toast(t, { delay: 3000, autohide: true });
        bsToast.show();
      });
    });
  </script>
</body>
</html>"""

# SIGNUP_HTML (Same as before - included for completeness)
SIGNUP_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign Up - Digital Diary</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&family=Playfair+Display:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #8a4fff;
      --primary-light: #a67cff;
      --primary-dark: #6b2dcc;
      --secondary: #ff6b9d;
      --accent: #4fd1c5;
      --dark: #1a1a2e;
      --light: #f8f9fa;
      --gradient: linear-gradient(135deg, var(--primary), var(--secondary));
    }
    * {
      box-sizing: border-box;
    }
    body {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: 'Poppins', sans-serif;
      opacity: 0;
      transition: opacity 0.7s ease;
      padding: 1rem;
      position: relative;
      overflow-x: hidden;
    }
    body::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: url("data:image/svg+xml,%3Csvg width='100' height='100' viewBox='0 0 100 100' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11 18c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm48 25c3.866 0 7-3.134 7-7s-3.134-7-7-7-7 3.134-7 7 3.134 7 7 7zm-43-7c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm63 31c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM34 90c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zm56-76c1.657 0 3-1.343 3-3s-1.343-3-3-3-3 1.343-3 3 1.343 3 3 3zM12 86c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm28-65c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm23-11c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-6 60c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm29 22c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zM32 63c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm57-13c2.76 0 5-2.24 5-5s-2.24-5-5-5-5 2.24-5 5 2.24 5 5 5zm-9-21c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM60 91c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM35 41c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2zM12 60c1.105 0 2-.895 2-2s-.895-2-2-2-2 .895-2 2 .895 2 2 2z' fill='%23ffffff' fill-opacity='0.05' fill-rule='evenodd'/%3E%3C/svg%3E");
      opacity: 0.3;
    }
    .signup-card {
      background: rgba(255, 255, 255, 0.95);
      backdrop-filter: blur(10px);
      border-radius: 20px;
      box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
      padding: 2.5rem;
      width: 100%;
      max-width: 420px;
      animation: fadeIn 0.8s ease;
      border: 1px solid rgba(255, 255, 255, 0.2);
      position: relative;
      overflow: hidden;
    }
    .signup-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 5px;
      background: var(--gradient);
    }
    @keyframes fadeIn {
      from {opacity: 0; transform: translateY(20px);}
      to {opacity: 1; transform: translateY(0);}
    }
    .app-title {
      font-family: 'Playfair Display', serif;
      font-weight: 600;
      text-align: center;
      margin-bottom: 2rem;
      color: var(--dark);
      font-size: 2.2rem;
      position: relative;
      display: inline-block;
      width: 100%;
    }
    .app-title::after {
      content: '';
      position: absolute;
      bottom: -10px;
      left: 50%;
      transform: translateX(-50%);
      width: 60px;
      height: 3px;
      background: var(--gradient);
      border-radius: 3px;
    }
    .form-label {
      font-weight: 500;
      color: var(--dark);
      margin-bottom: 0.5rem;
    }
    .form-control {
      border-radius: 10px;
      padding: 0.75rem 1rem;
      border: 1px solid #e1e5e9;
      transition: all 0.3s ease;
      font-size: 1rem;
    }
    .form-control:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 0.25rem rgba(138, 79, 255, 0.25);
    }
    .btn-signup {
      background: var(--gradient);
      border: none;
      border-radius: 10px;
      padding: 0.75rem;
      font-weight: 600;
      font-size: 1rem;
      transition: all 0.3s ease;
      box-shadow: 0 4px 15px rgba(138, 79, 255, 0.4);
      color: white;
    }
    .btn-signup:hover {
      transform: translateY(-2px);
      box-shadow: 0 6px 20px rgba(138, 79, 255, 0.5);
    }
    .btn-login {
      background: transparent;
      border: 2px solid var(--primary);
      border-radius: 10px;
      padding: 0.75rem;
      font-weight: 600;
      font-size: 1rem;
      transition: all 0.3s ease;
      color: var(--primary);
    }
    .btn-login:hover {
      background: var(--primary);
      color: white;
      transform: translateY(-2px);
    }
    .toast {
      border-radius: 10px;
      border: none;
    }
    .floating-shapes {
      position: absolute;
      width: 100%;
      height: 100%;
      overflow: hidden;
      z-index: -1;
    }
    .shape {
      position: absolute;
      opacity: 0.1;
      border-radius: 50%;
    }
    .shape-1 {
      width: 300px;
      height: 300px;
      background: var(--primary);
      top: -150px;
      right: -150px;
    }
    .shape-2 {
      width: 200px;
      height: 200px;
      background: var(--secondary);
      bottom: -100px;
      left: -100px;
    }
    .auth-switch {
      text-align: center;
      margin-top: 1.5rem;
      padding-top: 1.5rem;
      border-top: 1px solid #e1e5e9;
    }
    .password-strength {
      height: 4px;
      border-radius: 2px;
      margin-top: 0.25rem;
      transition: all 0.3s ease;
    }
  </style>
</head>
<body>
  <div class="floating-shapes">
    <div class="shape shape-1"></div>
    <div class="shape shape-2"></div>
  </div>
  <div class="signup-card">
    <h1 class="app-title">Create Account</h1>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <div class="mb-3">
        <label class="form-label">Username</label>
        <input type="text" name="username" class="form-control" required autofocus minlength="3" maxlength="20">
        <div class="form-text">3-20 characters, letters and numbers only</div>
      </div>
      <div class="mb-3">
        <label class="form-label">Password</label>
        <input type="password" name="password" class="form-control" required minlength="6" id="password">
        <div class="form-text">At least 6 characters</div>
        <div class="password-strength" id="passwordStrength"></div>
      </div>
      <div class="mb-4">
        <label class="form-label">Confirm Password</label>
        <input type="password" name="confirm_password" class="form-control" required id="confirmPassword">
        <div class="form-text" id="passwordMatch"></div>
      </div>
      <button class="btn btn-signup w-100 text-white mb-3" id="submitBtn">Create Account</button>
    </form>

    <div class="auth-switch">
      <p class="text-muted mb-3">Already have an account?</p>
      <a href="{{ url_for('login') }}" class="btn btn-login w-100">Back to Login</a>
    </div>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, msg in messages %}
        <div class="toast align-items-center text-bg-{{ category }} border-0 show mt-3" role="alert">
          <div class="d-flex">
            <div class="toast-body">{{ msg }}</div>
          </div>
        </div>
      {% endfor %}
    {% endwith %}
  </div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      document.body.style.opacity = 0;
      setTimeout(() => document.body.style.opacity = 1, 50);

      const form = document.querySelector('form');
      form.addEventListener('submit', e => {
        e.preventDefault();
        document.body.style.transition = "opacity 0.7s ease, transform 0.7s ease";
        document.body.style.opacity = 0;
        document.body.style.transform = "translateX(-50px)";
        setTimeout(() => form.submit(), 700);
      });

      document.querySelector('.btn-login').addEventListener('click', e => {
        e.preventDefault();
        const url = e.target.href;
        document.body.style.transition = "opacity 0.7s ease, transform 0.7s ease";
        document.body.style.opacity = 0;
        document.body.style.transform = "translateX(50px)";
        setTimeout(() => window.location.href = url, 700);
      });

      const passwordInput = document.getElementById('password');
      const strengthBar = document.getElementById('passwordStrength');
      const confirmInput = document.getElementById('confirmPassword');
      const matchText = document.getElementById('passwordMatch');

      function checkPasswordStrength(password) {
        let strength = 0;
        if (password.length >= 6) strength += 1;
        if (password.length >= 8) strength += 1;
        if (/[A-Z]/.test(password)) strength += 1;
        if (/[0-9]/.test(password)) strength += 1;
        if (/[^A-Za-z0-9]/.test(password)) strength += 1;

        return strength;
      }

      function updatePasswordStrength() {
        const password = passwordInput.value;
        const strength = checkPasswordStrength(password);

        let color = '#dc3545';
        let width = '20%';

        if (strength >= 4) {
          color = '#28a745';
          width = '100%';
        } else if (strength >= 3) {
          color = '#ffc107';
          width = '75%';
        } else if (strength >= 2) {
          color = '#fd7e14';
          width = '50%';
        } else if (strength >= 1) {
          color = '#dc3545';
          width = '25%';
        }

        strengthBar.style.width = width;
        strengthBar.style.backgroundColor = color;
      }

      function checkPasswordMatch() {
        const password = passwordInput.value;
        const confirm = confirmInput.value;

        if (confirm === '') {
          matchText.textContent = '';
          matchText.className = 'form-text';
        } else if (password === confirm) {
          matchText.textContent = '✓ Passwords match';
          matchText.className = 'form-text text-success';
        } else {
          matchText.textContent = '✗ Passwords do not match';
          matchText.className = 'form-text text-danger';
        }
      }

      passwordInput.addEventListener('input', updatePasswordStrength);
      passwordInput.addEventListener('input', checkPasswordMatch);
      confirmInput.addEventListener('input', checkPasswordMatch);

      document.querySelectorAll('.toast').forEach(t => {
        const bsToast = new bootstrap.Toast(t, { delay: 3000, autohide: true });
        bsToast.show();
      });
    });
  </script>
</body>
</html>"""


# INDEX PAGE (Dashboard)
INDEX_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Digital Diary Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&family=Playfair+Display:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #8a4fff;
      --primary-light: #a67cff;
      --primary-dark: #6b2dcc;
      --secondary: #ff6b9d;
      --accent: #4fd1c5;
      --dark: #1a1a2e;
      --light: #f8f9fa;
      --gradient: linear-gradient(135deg, var(--primary), var(--secondary));
      --card-gradient: linear-gradient(135deg, #ffffff, #f8f9fa);
      --shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      --shadow-hover: 0 15px 40px rgba(0, 0, 0, 0.12);
    }
    [data-bs-theme="light"] {
      --bg-color: #f8f9fa;
      --text-color: #1a1a2e;
      --card-bg: #ffffff;
      --navbar-bg: #ffffff;
      --border-color: #e1e5e9;
    }
    [data-bs-theme="dark"] {
      --bg-color: #121212;
      --text-color: #f8f9fa;
      --card-bg: #1e1e1e;
      --navbar-bg: #1a1a1a;
      --border-color: #333333;
    }
    * {
      box-sizing: border-box;
    }
    body {
      font-family: 'Poppins', sans-serif;
      background-color: var(--bg-color);
      color: var(--text-color);
      opacity: 0;
      transition: opacity 0.8s ease, background-color 0.5s ease, color 0.5s ease;
      min-height: 100vh;
    }
    body.fade-in {
      opacity: 1;
    }
    .navbar {
      background-color: var(--navbar-bg) !important;
      backdrop-filter: blur(10px);
      box-shadow: 0 2px 15px rgba(0, 0, 0, 0.1);
      border-bottom: 1px solid var(--border-color);
      padding: 1rem 0;
    }
    .navbar-brand {
      font-family: 'Playfair Display', serif;
      font-weight: 600;
      font-size: 1.5rem;
      color: var(--primary) !important;
    }
    .card {
  background: var(--card-bg); /* Changed from card-gradient to card-bg */
  border-radius: 16px;
  transition: all 0.3s ease;
  border: 1px solid var(--border-color);
  box-shadow: var(--shadow);
  overflow: hidden;
  height: 100%;
}
    .card:hover {
      transform: translateY(-8px);
      box-shadow: var(--shadow-hover);
    }
    .card-body {
      padding: 1.5rem;
    }
    .card-title {
  font-weight: 600;
  color: var(--card-title-color);
  font-size: 1.1rem;
  margin-bottom: 0.75rem;
}

[data-bs-theme="light"] {
  --bg-color: #f8f9fa;
  --text-color: #1a1a2e;
  --card-bg: #ffffff;
  --navbar-bg: #ffffff;
  --border-color: #e1e5e9;
  --card-title-color: #1a1a2e;
}
[data-bs-theme="dark"] {
  --bg-color: #1a1a2e;      /* Dark background */
  --text-color: #f8f9fa;    /* Light text */
  --card-bg: #2d2d2d;       /* Dark cards */
  --navbar-bg: #2d2d2d;     /* Dark navbar */
  --border-color: #444444;  /* Dark borders */
  --card-title-color: #f8f9fa; /* Light text on dark cards */
}
    .card-text {
      color: #6c757d;
      font-size: 0.85rem;
    }
    .floating-btn {
      position: fixed;
      bottom: 25px;
      right: 25px;
      background: var(--gradient);
      color: white;
      border-radius: 50%;
      width: 60px;
      height: 60px;
      border: none;
      font-size: 1.5rem;
      box-shadow: 0 6px 20px rgba(138, 79, 255, 0.4);
      transition: all 0.3s ease;
      z-index: 1000;
    }
    .floating-btn:hover {
      transform: scale(1.1);
      box-shadow: 0 8px 25px rgba(138, 79, 255, 0.6);
    }
    .toast-container {
      position: fixed;
      top: 1rem;
      right: 1rem;
      z-index: 1055;
    }
    .btn-outline-primary {
      border-color: var(--primary);
      color: var(--primary);
    }
    .btn-outline-primary:hover {
      background-color: var(--primary);
      border-color: var(--primary);
    }
    .btn-outline-info {
      border-color: var(--accent);
      color: var(--accent);
    }
    .btn-outline-info:hover {
      background-color: var(--accent);
      border-color: var(--accent);
    }
    .btn-outline-success {
      border-color: #28a745;
      color: #28a745;
    }
    .btn-outline-success:hover {
      background-color: #28a745;
      border-color: #28a745;
    }
    .btn-outline-warning {
      border-color: #ffc107;
      color: #ffc107;
    }
    .btn-outline-warning:hover {
      background-color: #ffc107;
      border-color: #ffc107;
      color: #000;
    }
    .btn-outline-danger {
      border-color: #dc3545;
      color: #dc3545;
    }
    .btn-outline-danger:hover {
      background-color: #dc3545;
      border-color: #dc3545;
    }
    .search-box {
      border-radius: 10px;
      border: 1px solid var(--border-color);
      padding: 0.5rem 1rem;
      transition: all 0.3s ease;
    }
    .search-box:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 0.25rem rgba(138, 79, 255, 0.25);
    }
    .modal-content {
      border-radius: 16px;
      border: none;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
    }
    .modal-header {
      border-bottom: 1px solid var(--border-color);
    }
    .modal-footer {
      border-top: 1px solid var(--border-color);
    }
    .empty-state {
      text-align: center;
      padding: 3rem 1rem;
      color: #6c757d;
    }
    .empty-state i {
      font-size: 4rem;
      margin-bottom: 1rem;
      color: var(--primary-light);
      opacity: 0.7;
    }
    .diary-icon {
      color: var(--primary);
      font-size: 1.2rem;
    }
    .user-badge {
      background: var(--gradient);
      color: white;
      border-radius: 20px;
      padding: 0.3rem 1rem;
      font-size: 0.9rem;
      font-weight: 500;
    }
    .theme-toggle {
      background: transparent;
      border: 1px solid var(--border-color);
      border-radius: 50%;
      width: 40px;
      height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.3s ease;
    }
    .theme-toggle:hover {
      background-color: rgba(138, 79, 255, 0.1);
      border-color: var(--primary);
    }
    .page-title {
      font-family: 'Playfair Display', serif;
      font-weight: 600;
      color: var(--text-color);
      position: relative;
      display: inline-block;
    }
    .page-title::after {
      content: '';
      position: absolute;
      bottom: -8px;
      left: 0;
      width: 50px;
      height: 3px;
      background: var(--gradient);
      border-radius: 3px;
    }
  </style>
</head>
<body data-bs-theme="light">
  <nav class="navbar navbar-expand-lg shadow-sm">
    <div class="container">
      <a class="navbar-brand" href="#"><i class="bi bi-journal-text me-2"></i>Digital Diary</a>
      <div class="d-flex align-items-center">
        <button class="btn theme-toggle me-3" id="themeToggle"><i class="bi bi-moon"></i></button>
        <span class="user-badge me-3"><i class="bi bi-person-circle me-1"></i>{{ session.username }}</span>
        <a href="{{ url_for('logout') }}" class="btn btn-outline-primary btn-sm">Logout</a>
      </div>
    </div>
  </nav>

  <div class="container py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
      <h2 class="page-title">Your Diaries</h2>
      <form class="d-flex" action="{{ url_for('search') }}" method="get">
        <input class="form-control search-box me-2" type="search" name="q" placeholder="Search diaries...">
        <button class="btn btn-primary" type="submit"><i class="bi bi-search"></i></button>
      </form>
    </div>

    <div class="toast-container">
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% for category, msg in messages %}
          <div class="toast text-bg-{{ category }} border-0" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="d-flex">
              <div class="toast-body">{{ msg }}</div>
              <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
          </div>
        {% endfor %}
      {% endwith %}
    </div>

    {% if files %}
      <div class="row">
        {% for f in files %}
          <div class="col-md-4 mb-4">
            <div class="card shadow-sm">
              <div class="card-body">
                <h5 class="card-title"><i class="bi bi-journal diary-icon me-2"></i>{{ f.replace('_', ' ').replace('.txt', '') }}</h5>
                <p class="card-text"><small class="text-muted">{{ modtimes[f] }} | {{ file_sizes[f] }} KB</small></p>
                <div class="d-flex justify-content-between">
                  <a href="{{ url_for('view', name=f) }}" class="btn btn-outline-info btn-sm page-link-smooth">View</a>
                  <a href="{{ url_for('download', name=f) }}" class="btn btn-outline-success btn-sm">Download</a>
                  <a href="{{ url_for('edit', name=f) }}" class="btn btn-outline-warning btn-sm">Edit</a>
                  <a href="#" class="btn btn-outline-danger btn-sm delete-btn" data-diary="{{ f }}">Delete</a>
                </div>
              </div>
            </div>
          </div>
        {% endfor %}
      </div>
    {% else %}
      <div class="empty-state">
        <i class="bi bi-journal-x"></i>
        <h3>No diaries yet</h3>
        <p>Create your first diary to get started!</p>
      </div>
    {% endif %}
  </div>

  <button class="floating-btn" data-bs-toggle="modal" data-bs-target="#createModal"><i class="bi bi-plus"></i></button>

  <!-- Create Diary Modal -->
  <div class="modal fade" id="createModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Create New Diary</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <form method="post" action="{{ url_for('create') }}">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <div class="mb-3">
              <label class="form-label">Diary Name</label>
              <input class="form-control" name="name" placeholder="My Secret Diary" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Initial Content</label>
              <textarea class="form-control" name="content" rows="4" placeholder="Dear Diary..."></textarea>
            </div>
            <button class="btn btn-primary w-100">Create Diary</button>
          </form>
        </div>
      </div>
    </div>
  </div>

  <!-- Delete Confirmation Modal -->
  <div class="modal fade" id="deleteModal" tabindex="-1">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title text-danger"><i class="bi bi-exclamation-triangle me-2"></i>Confirm Delete</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <p>Are you sure you want to delete "<span id="diaryToDelete"></span>"? This action cannot be undone.</p>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
          <a href="#" class="btn btn-danger" id="confirmDeleteBtn">Delete</a>
        </div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      document.body.classList.add('fade-in');

      document.querySelectorAll('.page-link-smooth').forEach(link => {
        link.addEventListener('click', e => {
          e.preventDefault();
          const url = link.href;
          document.body.style.transition = "transform 0.7s ease, opacity 0.7s ease";
          document.body.style.transform = "translateX(-50px)";
          document.body.style.opacity = 0;
          setTimeout(() => window.location.href = url, 700);
        });
      });

      document.querySelectorAll('.toast').forEach(t => {
        const bsToast = new bootstrap.Toast(t, { delay: 3000, autohide: true });
        bsToast.show();
      });

      const toggleBtn = document.getElementById('themeToggle');
      const currentTheme = localStorage.getItem('theme') || 'light';
      document.body.setAttribute('data-bs-theme', currentTheme);
      toggleBtn.innerHTML = currentTheme === 'light' ? '<i class="bi bi-moon"></i>' : '<i class="bi bi-sun"></i>';

      toggleBtn.addEventListener('click', () => {
        const current = document.body.getAttribute('data-bs-theme');
        const next = current === 'light' ? 'dark' : 'light';

        document.body.style.transition = "opacity 0.3s ease";
        document.body.style.opacity = 0;

        setTimeout(() => {
          document.body.setAttribute('data-bs-theme', next);
          localStorage.setItem('theme', next);
          toggleBtn.innerHTML = next === 'light' ? '<i class="bi bi-moon"></i>' : '<i class="bi bi-sun"></i>';

          document.body.style.transition = "opacity 0.3s ease, background-color 0.5s ease, color 0.5s ease";
          document.body.style.opacity = 1;
        }, 300);
      });

      document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', e => {
          e.preventDefault();
          const diaryName = btn.getAttribute('data-diary');
          const displayName = diaryName.replace(/_/g, ' ').replace('.txt', '');
          document.getElementById('diaryToDelete').textContent = displayName;
          const confirmBtn = document.getElementById('confirmDeleteBtn');
          confirmBtn.href = `/delete/${encodeURIComponent(diaryName)}`;
          const deleteModal = new bootstrap.Modal(document.getElementById('deleteModal'));
          deleteModal.show();
        });
      });
    });

    window.addEventListener('pageshow', (event) => {
      if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
        document.body.style.opacity = 1;
        document.body.style.transform = "translateX(0)";
        document.body.classList.add('fade-in');
      }
    });
  </script>
</body>
</html>"""

# VIEW PAGE
VIEW_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ name.replace('_', ' ').replace('.txt', '') }} - Digital Diary</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&family=Playfair+Display:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #8a4fff;
      --primary-light: #a67cff;
      --primary-dark: #6b2dcc;
      --secondary: #ff6b9d;
      --accent: #4fd1c5;
      --dark: #1a1a2e;
      --light: #f8f9fa;
      --gradient: linear-gradient(135deg, var(--primary), var(--secondary));
      --card-gradient: linear-gradient(135deg, #ffffff, #f8f9fa);
      --shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      --shadow-hover: 0 15px 40px rgba(0, 0, 0, 0.12);
    }
    [data-bs-theme="light"] {
      --bg-color: #f8f9fa;
      --text-color: #1a1a2e;
      --card-bg: #ffffff;
      --navbar-bg: #ffffff;
      --border-color: #e1e5e9;
      --content-color: #333;
    }
    [data-bs-theme="dark"] {
      --bg-color: #121212;
      --text-color: #f8f9fa;
      --card-bg: #1e1e1e;
      --navbar-bg: #1a1a1a;
      --border-color: #333333;
      --content-color: #e0e0e0;
    }
    * {
      box-sizing: border-box;
    }
    body {
      font-family: 'Poppins', sans-serif;
      background-color: var(--bg-color);
      color: var(--text-color);
      min-height: 100vh;
      opacity: 0;
      transition: opacity 0.8s ease, background-color 0.5s ease, color 0.5s ease;
      padding: 2rem;
    }
    body.fade-in {
      opacity: 1;
    }
    .navbar {
      background-color: var(--navbar-bg) !important;
      backdrop-filter: blur(10px);
      box-shadow: 0 2px 15px rgba(0, 0, 0, 0.1);
      border-bottom: 1px solid var(--border-color);
      padding: 1rem 0;
      margin-bottom: 2rem;
    }
    .navbar-brand {
      font-family: 'Playfair Display', serif;
      font-weight: 600;
      font-size: 1.5rem;
      color: var(--primary) !important;
    }
    .diary-card {
      background: var(--card-bg);
      border-radius: 16px;
      box-shadow: var(--shadow);
      border: 1px solid var(--border-color);
      padding: 2rem;
      max-width: 900px;
      margin: auto;
      transition: all 0.3s ease;
    }
    .diary-card:hover {
      transform: translateY(-5px);
      box-shadow: var(--shadow-hover);
    }
    .diary-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
    }
    .diary-title {
      font-family: 'Playfair Display', serif;
      font-weight: 600;
      font-size: 1.8rem;
      color: var(--text-color);
      margin: 0;
    }
    .btn-group-top button, .btn-group-top a {
      margin-left: 0.5rem;
      border-radius: 8px;
      font-weight: 500;
    }
    .btn-copy {
      background: var(--gradient);
      border: none;
      color: white;
    }
    .btn-copy:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 10px rgba(138, 79, 255, 0.3);
    }
    .diary-content {
      font-family: 'Poppins', sans-serif;
      font-size: 1rem;
      line-height: 1.6;
      color: var(--content-color);
      white-space: pre-line;
      word-wrap: break-word;
      background: transparent;
      border: none;
      padding: 0;
    }
    .toast-container {
      position: fixed;
      bottom: 1rem;
      right: 1rem;
      z-index: 1055;
    }
    .user-badge {
      background: var(--gradient);
      color: white;
      border-radius: 20px;
      padding: 0.3rem 1rem;
      font-size: 0.9rem;
      font-weight: 500;
    }
    .theme-toggle {
      background: transparent;
      border: 1px solid var(--border-color);
      border-radius: 50%;
      width: 40px;
      height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.3s ease;
      color: var(--text-color);
    }
    .theme-toggle:hover {
      background-color: rgba(138, 79, 255, 0.1);
      border-color: var(--primary);
    }
    .page-link-smooth {
      transition: all 0.3s ease;
    }
  </style>
</head>
<body data-bs-theme="light">
  <nav class="navbar navbar-expand-lg shadow-sm">
    <div class="container">
      <a class="navbar-brand" href="{{ url_for('index') }}"><i class="bi bi-journal-text me-2"></i>Digital Diary</a>
      <div class="d-flex align-items-center">
        <button class="btn theme-toggle me-3" id="themeToggle"><i class="bi bi-moon"></i></button>
        <span class="user-badge me-3"><i class="bi bi-person-circle me-1"></i>{{ session.username }}</span>
        <a href="{{ url_for('logout') }}" class="btn btn-outline-primary btn-sm">Logout</a>
      </div>
    </div>
  </nav>

  <div class="diary-card">
    <div class="diary-header">
      <h3 class="diary-title"><i class="bi bi-journal-text me-2"></i>{{ name.replace('_', ' ').replace('.txt', '') }}</h3>
      <div class="btn-group-top">
        <button class="btn btn-copy btn-sm" onclick="copyDiary()"><i class="bi bi-clipboard me-1"></i> Copy</button>
        <a href="{{ url_for('edit', name=name) }}" class="btn btn-outline-warning btn-sm"><i class="bi bi-pencil me-1"></i> Edit</a>
        <a href="{{ url_for('index') }}" class="btn btn-outline-primary btn-sm page-link-smooth"><i class="bi bi-arrow-left me-1"></i> Back</a>
      </div>
    </div>
    <div class="diary-content" id="diaryContent">{{ content }}</div>
  </div>

  <div class="toast-container">
    <div id="copyToast" class="toast text-bg-success border-0">
      <div class="d-flex">
        <div class="toast-body"><i class="bi bi-check-circle me-2"></i>Copied to clipboard!</div>
      </div>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    function copyDiary() {
      const content = document.getElementById('diaryContent').innerText;
      navigator.clipboard.writeText(content).then(() => {
        const toastEl = document.getElementById('copyToast');
        const bsToast = new bootstrap.Toast(toastEl, { delay: 2000, autohide: true });
        bsToast.show();
      });
    }

    document.addEventListener('DOMContentLoaded', () => {
      document.body.style.opacity = 1;
      document.body.classList.add('fade-in');

      // Theme toggle functionality
      const toggleBtn = document.getElementById('themeToggle');
      const currentTheme = localStorage.getItem('theme') || 'light';
      document.body.setAttribute('data-bs-theme', currentTheme);
      toggleBtn.innerHTML = currentTheme === 'light' ? '<i class="bi bi-moon"></i>' : '<i class="bi bi-sun"></i>';

      toggleBtn.addEventListener('click', () => {
        const current = document.body.getAttribute('data-bs-theme');
        const next = current === 'light' ? 'dark' : 'light';

        document.body.style.transition = "opacity 0.3s ease";
        document.body.style.opacity = 0;

        setTimeout(() => {
          document.body.setAttribute('data-bs-theme', next);
          localStorage.setItem('theme', next);
          toggleBtn.innerHTML = next === 'light' ? '<i class="bi bi-moon"></i>' : '<i class="bi bi-sun"></i>';

          document.body.style.transition = "opacity 0.3s ease, background-color 0.5s ease, color 0.5s ease";
          document.body.style.opacity = 1;
        }, 300);
      });

      document.querySelectorAll('.page-link-smooth').forEach(link => {
        link.addEventListener('click', e => {
          e.preventDefault();
          const url = link.href;
          document.body.style.transition = "transform 0.7s ease, opacity 0.7s ease";
          document.body.style.transform = "translateX(-50px)";
          document.body.style.opacity = 0;
          setTimeout(() => window.location.href = url, 700);
        });
      });
    });

    window.addEventListener('pageshow', (event) => {
      if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
        document.body.style.opacity = 1;
        document.body.style.transform = "translateX(0)";
        document.body.classList.add('fade-in');
      }
    });
  </script>
</body>
</html>"""

# EDIT PAGE
EDIT_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Edit {{ name.replace('_', ' ').replace('.txt', '') }} - Digital Diary</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&family=Playfair+Display:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #8a4fff;
      --primary-light: #a67cff;
      --primary-dark: #6b2dcc;
      --secondary: #ff6b9d;
      --accent: #4fd1c5;
      --dark: #1a1a2e;
      --light: #f8f9fa;
      --gradient: linear-gradient(135deg, var(--primary), var(--secondary));
      --card-gradient: linear-gradient(135deg, #ffffff, #f8f9fa);
      --shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
      --shadow-hover: 0 15px 40px rgba(0, 0, 0, 0.12);
    }
    [data-bs-theme="light"] {
      --bg-color: #f8f9fa;
      --text-color: #1a1a2e;
      --card-bg: #ffffff;
      --navbar-bg: #ffffff;
      --border-color: #e1e5e9;
      --input-bg: #ffffff;
      --input-color: #1a1a2e;
      --input-border: #e1e5e9;
    }
    [data-bs-theme="dark"] {
      --bg-color: #121212;
      --text-color: #f8f9fa;
      --card-bg: #1e1e1e;
      --navbar-bg: #1a1a1a;
      --border-color: #333333;
      --input-bg: #2d2d2d;
      --input-color: #f8f9fa;
      --input-border: #444444;
    }
    * {
      box-sizing: border-box;
    }
    body {
      font-family: 'Poppins', sans-serif;
      background-color: var(--bg-color);
      color: var(--text-color);
      min-height: 100vh;
      opacity: 0;
      transition: opacity 0.8s ease, background-color 0.5s ease, color 0.5s ease;
      padding: 2rem;
    }
    body.fade-in {
      opacity: 1;
    }
    .navbar {
      background-color: var(--navbar-bg) !important;
      backdrop-filter: blur(10px);
      box-shadow: 0 2px 15px rgba(0, 0, 0, 0.1);
      border-bottom: 1px solid var(--border-color);
      padding: 1rem 0;
      margin-bottom: 2rem;
    }
    .navbar-brand {
      font-family: 'Playfair Display', serif;
      font-weight: 600;
      font-size: 1.5rem;
      color: var(--primary) !important;
    }
    .diary-card {
      background: var(--card-bg);
      border-radius: 16px;
      box-shadow: var(--shadow);
      border: 1px solid var(--border-color);
      padding: 2rem;
      max-width: 900px;
      margin: auto;
      transition: all 0.3s ease;
    }
    .diary-card:hover {
      transform: translateY(-5px);
      box-shadow: var(--shadow-hover);
    }
    .diary-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1.5rem;
    }
    .diary-title {
      font-family: 'Playfair Display', serif;
      font-weight: 600;
      font-size: 1.8rem;
      color: var(--text-color);
      margin: 0;
    }
    .btn-group-top button, .btn-group-top a {
      margin-left: 0.5rem;
      border-radius: 8px;
      font-weight: 500;
    }
    .form-control {
      border-radius: 10px;
      padding: 0.75rem 1rem;
      border: 1px solid var(--input-border);
      transition: all 0.3s ease;
      font-size: 1rem;
      background-color: var(--input-bg);
      color: var(--input-color);
    }
    .form-control:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 0.25rem rgba(138, 79, 255, 0.25);
      background-color: var(--input-bg);
      color: var(--input-color);
    }
    textarea.form-control {
      min-height: 400px;
      font-family: 'Poppins', sans-serif;
      line-height: 1.6;
      white-space: pre-wrap;
    }
    .form-label {
      color: var(--text-color);
      font-weight: 500;
    }
    .user-badge {
      background: var(--gradient);
      color: white;
      border-radius: 20px;
      padding: 0.3rem 1rem;
      font-size: 0.9rem;
      font-weight: 500;
    }
    .theme-toggle {
      background: transparent;
      border: 1px solid var(--border-color);
      border-radius: 50%;
      width: 40px;
      height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.3s ease;
      color: var(--text-color);
    }
    .theme-toggle:hover {
      background-color: rgba(138, 79, 255, 0.1);
      border-color: var(--primary);
    }
    .page-link-smooth {
      transition: all 0.3s ease;
    }
  </style>
</head>
<body data-bs-theme="light">
  <nav class="navbar navbar-expand-lg shadow-sm">
    <div class="container">
      <a class="navbar-brand" href="{{ url_for('index') }}"><i class="bi bi-journal-text me-2"></i>Digital Diary</a>
      <div class="d-flex align-items-center">
        <button class="btn theme-toggle me-3" id="themeToggle"><i class="bi bi-moon"></i></button>
        <span class="user-badge me-3"><i class="bi bi-person-circle me-1"></i>{{ session.username }}</span>
        <a href="{{ url_for('logout') }}" class="btn btn-outline-primary btn-sm">Logout</a>
      </div>
    </div>
  </nav>

  <div class="diary-card">
    <div class="diary-header">
      <h3 class="diary-title"><i class="bi bi-pencil-square me-2"></i>Edit {{ name.replace('_', ' ').replace('.txt', '') }}</h3>
      <div class="btn-group-top">
        <a href="{{ url_for('view', name=name) }}" class="btn btn-outline-secondary btn-sm"><i class="bi bi-eye me-1"></i> Preview</a>
        <a href="{{ url_for('index') }}" class="btn btn-outline-primary btn-sm page-link-smooth"><i class="bi bi-arrow-left me-1"></i> Back</a>
      </div>
    </div>

    <form method="post" action="{{ url_for('update', name=name) }}">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <div class="mb-3">
        <label class="form-label">Diary Content</label>
        <textarea class="form-control" name="content" rows="20" placeholder="Write your diary entry here...">{{ content }}</textarea>
      </div>
      <div class="d-flex justify-content-between">
        <button type="submit" class="btn btn-success"><i class="bi bi-check-circle me-1"></i> Save Changes</button>
        <a href="{{ url_for('view', name=name) }}" class="btn btn-outline-secondary">Cancel</a>
      </div>
    </form>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      document.body.style.opacity = 1;
      document.body.classList.add('fade-in');

      // Theme toggle functionality
      const toggleBtn = document.getElementById('themeToggle');
      const currentTheme = localStorage.getItem('theme') || 'light';
      document.body.setAttribute('data-bs-theme', currentTheme);
      toggleBtn.innerHTML = currentTheme === 'light' ? '<i class="bi bi-moon"></i>' : '<i class="bi bi-sun"></i>';

      toggleBtn.addEventListener('click', () => {
        const current = document.body.getAttribute('data-bs-theme');
        const next = current === 'light' ? 'dark' : 'light';

        document.body.style.transition = "opacity 0.3s ease";
        document.body.style.opacity = 0;

        setTimeout(() => {
          document.body.setAttribute('data-bs-theme', next);
          localStorage.setItem('theme', next);
          toggleBtn.innerHTML = next === 'light' ? '<i class="bi bi-moon"></i>' : '<i class="bi bi-sun"></i>';

          document.body.style.transition = "opacity 0.3s ease, background-color 0.5s ease, color 0.5s ease";
          document.body.style.opacity = 1;
        }, 300);
      });

      document.querySelectorAll('.page-link-smooth').forEach(link => {
        link.addEventListener('click', e => {
          e.preventDefault();
          const url = link.href;
          document.body.style.transition = "transform 0.7s ease, opacity 0.7s ease";
          document.body.style.transform = "translateX(-50px)";
          document.body.style.opacity = 0;
          setTimeout(() => window.location.href = url, 700);
        });
      });

      document.querySelector('textarea').focus();
    });

    window.addEventListener('pageshow', (event) => {
      if (event.persisted || performance.getEntriesByType("navigation")[0].type === "back_forward") {
        document.body.style.opacity = 1;
        document.body.style.transform = "translateX(0)";
        document.body.classList.add('fade-in');
      }
    });
  </script>
</body>
</html>
"""



# --- ROUTES ---
@app.route("/")
def home():
    if 'username' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == "POST":
        # Rate limiting for login attempts
        if 'login_attempts' not in session:
            session['login_attempts'] = 0
            session['last_login_attempt'] = datetime.now().timestamp()

        if session['login_attempts'] >= 5:
            time_diff = datetime.now().timestamp() - session['last_login_attempt']
            if time_diff < 300:
                flash('Too many login attempts. Please try again later.', 'danger')
                return render_template_string(LOGIN_HTML)
            else:
                session['login_attempts'] = 0

        username = request.form["username"].strip()
        password = request.form["password"]

        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return render_template_string(LOGIN_HTML)

        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, username, password_hash FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session["username"] = user['username']
            session['user_id'] = user['id']
            session['login_attempts'] = 0

            # Update last login
            cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
            db.commit()

            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("index"))
        else:
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            session['last_login_attempt'] = datetime.now().timestamp()
            flash("Invalid username or password", "danger")

    return render_template_string(LOGIN_HTML)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if 'username' in session:
        return redirect(url_for('index'))

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not validate_username(username):
            flash("Username must be 3-20 characters and contain only letters, numbers, and underscores", "danger")
        elif len(password) < 6:
            flash("Password must be at least 6 characters long", "danger")
        elif password != confirm_password:
            flash("Passwords do not match", "danger")
        else:
            db = get_db()
            cursor = db.cursor()

            # Check if username exists
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                flash("Username already exists", "danger")
            else:
                # Create new user
                password_hash = generate_password_hash(password)
                cursor.execute(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, password_hash)
                )
                db.commit()

                # Create user directory
                get_user_dir(username)

                flash("Account created successfully! Please login.", "success")
                return redirect(url_for('login'))

    return render_template_string(SIGNUP_HTML)

@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def index():
    username = session['username']
    user_id = session['user_id']

    db = get_db()
    cursor = db.cursor()

    # Get diaries from database
    cursor.execute('''
                   SELECT filename, title, content, file_size, created_at, updated_at
                   FROM diaries
                   WHERE user_id = ?
                   ORDER BY updated_at DESC
                   ''', (user_id,))

    diaries = cursor.fetchall()

    # Convert to format expected by template
    files = []
    modtimes = {}
    file_sizes = {}

    for diary in diaries:
        filename = diary['filename']
        files.append(filename)
        modtimes[filename] = diary['updated_at']
        file_sizes[filename] = "%.1f" % (diary['file_size'] / 1024) if diary['file_size'] else "0.0"

    return render_template_string(INDEX_HTML, files=files, modtimes=modtimes, file_sizes=file_sizes)

@app.route("/create", methods=["POST"])
@login_required
def create():
    username = session['username']
    user_id = session['user_id']

    # CSRF protection
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        flash("Invalid CSRF token", "danger")
        return redirect(url_for("index"))

    name = request.form.get("name", "").strip()

    if not name:
        flash("Diary name is required", "danger")
        return redirect(url_for("index"))

    # Secure filename creation
    safe_name = secure_filename(name)
    if not safe_name:
        flash("Invalid diary name", "danger")
        return redirect(url_for("index"))

    filename = safe_name + ".txt"

    if not validate_filename(filename):
        flash("Invalid diary name", "danger")
        return redirect(url_for("index"))

    user_dir = get_user_dir(username)
    if not user_dir:
        flash("Invalid user directory", "danger")
        return redirect(url_for('logout'))

    file_path = get_user_file_path(username, filename)
    if not file_path:
        flash("Invalid file path", "danger")
        return redirect(url_for("index"))

    # Check if diary already exists in database
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT id FROM diaries WHERE user_id = ? AND filename = ?', (user_id, filename))
    if cursor.fetchone():
        flash("Diary already exists!", "warning")
        return redirect(url_for("index"))

    content = request.form.get("content", "")
    sanitized_content = sanitize_content(content)
    if sanitized_content is None:
        flash("Diary content is too large or invalid", "danger")
        return redirect(url_for("index"))

    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Write to file
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(sanitized_content)

        # Save to database
        file_size = len(sanitized_content.encode('utf-8'))
        cursor.execute('''
                       INSERT INTO diaries (user_id, title, content, filename, file_path, file_size)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ''', (user_id, name, sanitized_content, filename, file_path, file_size))

        db.commit()
        flash("Diary created successfully!", "success")
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error creating diary: {str(e)}")
        flash("Error creating diary", "danger")

    return redirect(url_for("index"))

@app.route("/view/<name>")
@login_required
def view(name):
    username = session['username']
    user_id = session['user_id']

    if not validate_filename(name):
        flash("Invalid diary name", "danger")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT content FROM diaries WHERE user_id = ? AND filename = ?', (user_id, name))
    diary = cursor.fetchone()

    if not diary:
        flash("Diary not found!", "danger")
        return redirect(url_for("index"))

    return render_template_string(VIEW_HTML, name=name, content=diary['content'])

@app.route("/edit/<name>")
@login_required
def edit(name):
    username = session['username']
    user_id = session['user_id']

    if not validate_filename(name):
        flash("Invalid diary name", "danger")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT content FROM diaries WHERE user_id = ? AND filename = ?', (user_id, name))
    diary = cursor.fetchone()

    if not diary:
        flash("Diary not found!", "danger")
        return redirect(url_for("index"))

    return render_template_string(EDIT_HTML, name=name, content=diary['content'])

@app.route("/update/<name>", methods=["POST"])
@login_required
def update(name):
    username = session['username']
    user_id = session['user_id']

    # CSRF protection
    csrf_token = request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        flash("Invalid CSRF token", "danger")
        return redirect(url_for("index"))

    if not validate_filename(name):
        flash("Invalid diary name", "danger")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()

    # Check if diary exists
    cursor.execute('SELECT id, file_path FROM diaries WHERE user_id = ? AND filename = ?', (user_id, name))
    diary = cursor.fetchone()

    if not diary:
        flash("Diary not found!", "danger")
        return redirect(url_for("index"))

    content = request.form.get("content", "")
    sanitized_content = sanitize_content(content)
    if sanitized_content is None:
        flash("Diary content is too large or invalid", "danger")
        return redirect(url_for("index"))

    try:
        # Update file
        with open(diary['file_path'], "w", encoding="utf-8") as f:
            f.write(sanitized_content)

        # Update database
        file_size = len(sanitized_content.encode('utf-8'))
        cursor.execute('''
                       UPDATE diaries
                       SET content    = ?,
                           file_size  = ?,
                           updated_at = CURRENT_TIMESTAMP
                       WHERE id = ?
                       ''', (sanitized_content, file_size, diary['id']))

        db.commit()
        flash("Diary updated successfully!", "success")
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error updating diary: {str(e)}")
        flash("Error updating diary", "danger")

    return redirect(url_for("view", name=name))

@app.route("/download/<name>")
@login_required
def download(name):
    username = session['username']
    user_id = session['user_id']

    if not validate_filename(name):
        abort(404)

    user_dir = get_user_dir(username)
    if not user_dir:
        abort(404)

    file_path = get_user_file_path(username, name)
    if not file_path or not os.path.exists(file_path):
        abort(404)

    try:
        return send_from_directory(user_dir, name, as_attachment=True)
    except Exception as e:
        abort(404)

@app.route("/delete/<name>")
@login_required
def delete(name):
    username = session['username']
    user_id = session['user_id']

    if not validate_filename(name):
        flash("Invalid diary name", "danger")
        return redirect(url_for("index"))

    db = get_db()
    cursor = db.cursor()

    # Get diary info
    cursor.execute('SELECT id, file_path FROM diaries WHERE user_id = ? AND filename = ?', (user_id, name))
    diary = cursor.fetchone()

    if not diary:
        flash("Diary not found!", "danger")
        return redirect(url_for("index"))

    try:
        # Delete file
        if os.path.exists(diary['file_path']):
            os.remove(diary['file_path'])

        # Delete from database
        cursor.execute('DELETE FROM diaries WHERE id = ?', (diary['id'],))
        db.commit()

        flash("Diary deleted.", "danger")
    except Exception as e:
        db.rollback()
        app.logger.error(f"Error deleting diary: {str(e)}")
        flash("Error deleting diary", "danger")

    return redirect(url_for("index"))

@app.route("/search")
@login_required
def search():
    username = session['username']
    user_id = session['user_id']
    q = request.args.get("q", "").lower().strip()

    if len(q) > 100:
        q = q[:100]

    db = get_db()
    cursor = db.cursor()

    # Search in database
    cursor.execute('''
                   SELECT filename, title, updated_at, file_size
                   FROM diaries
                   WHERE user_id = ?
                     AND (title LIKE ? OR content LIKE ?)
                   ORDER BY updated_at DESC
                   ''', (user_id, f'%{q}%', f'%{q}%'))

    results = cursor.fetchall()

    # Convert to format expected by template
    files = []
    modtimes = {}
    file_sizes = {}

    for diary in results:
        filename = diary['filename']
        files.append(filename)
        modtimes[filename] = diary['updated_at']
        file_sizes[filename] = "%.1f" % (diary['file_size'] / 1024) if diary['file_size'] else "0.0"

    flash(f"{len(results)} result(s) for '{q}'", "info")
    return render_template_string(INDEX_HTML, files=files, modtimes=modtimes, file_sizes=file_sizes)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return "Page not found", 404

@app.errorhandler(413)
def too_large(error):
    flash("File too large", "danger")
    return redirect(request.url)

@app.errorhandler(500)
def internal_error(error):
    flash("Internal server error", "danger")
    return redirect(url_for('index'))

# Only run in development mode
if __name__ == '__main__':
    # This only runs when executed directly, not in production
    if os.environ.get('FLASK_ENV') == 'development':
        app.run(debug=True)
    else:
        print("Use a production WSGI server to run this application")
        print("Example: gunicorn wsgi:app")