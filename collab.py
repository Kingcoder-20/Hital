from flask import Flask, render_template, url_for, session, request, jsonify, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps 
import sqlite3
from flask_cors import CORS
import datetime 
import re
import uuid
import pytz

app = Flask(__name__)
app.secret_key = "FunnyMaster2008"
CORS(app)
DB_PATH = "Facebook.db"
def get_db ():
   conn = sqlite3.connect(
   DB_PATH,
   timeout=30,
   check_same_thread=False 
   )
   conn.row_factory = sqlite3.Row
   return conn 
def init_db():
   with get_db() as conn:
       conn.execute("""
       CREATE TABLE IF NOT EXISTS users (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       session_id TEXT NOT NULL,
       username TEXT NOT NULL,
       hash_password TEXT NOT NULL,
       email TEXT UNIQUE,
       avatar TEXT DEFAULT '',
       verified INTEGER DEFAULT 0,
       created_at TEXT NOT NULL
       )
       """)
       conn.commit()
init_db()  
def json_error(msg, code):
    return jsonify({
    "success": False,
    "message": msg
    }),code
    
def json_success(data=None):
    return jsonify({
    "success": True,
    "data": data
    }),200
DEFAULT_TIMEZONE = "Africa/Lagos"
def get_current_datetime():
    tz = pytz.timezone(DEFAULT_TIMEZONE)
    return datetime.datetime.now(tz).isoformat()
      
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            from flask import redirect, url_for
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrapper
    
@app.route("/")
def homepage():
    return render_template("index.html")

@app.route("/signup")
def signup_page():
    return render_template("signup.html")
    
@app.route("/login")
def login_page():
    return render_template("login.html")
    
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

@app.route("/dashboard/info")
@login_required
def dashboard_info():
    return jsonify({
        "success": True,
        "username": session.get("username"),
        "email": session.get("email"),
        "user_id": session.get("user_id")
    })
   
@app.route("/signup/endpoint", methods=["POST"])
def signup_endpoint():
    data = request.get_json() or {}
    username = data.get("username" ).strip()
    password = data.get("password")
    email = data.get("email").lower().strip() 
    if not username or not password or not email:
        return json_error("All fields are required ❗", 400)
    if len(username)<3:
        return json_error("Username too short ❗", 400)
    if len(username)>20:
        return json_error("Username too long ❗", 400)
    if len(password)<8:
        return json_error("Password must be at least 8 characters ❗", 400)
    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return json_error("invalid email ❗", 400)
    hash_password = generate_password_hash(password)
    session_id = str(uuid.uuid4())
    try:
        with get_db() as conn:
            existing = conn.execute("""
            SELECT id FROM users WHERE email = ? 
            """,(email,)).fetchone()
            if existing:
                return json_error("User already exists", 409)
            conn.execute("""
            INSERT INTO users (session_id, 
            username, 
            hash_password, 
            email,
            created_at) VALUES (?,?,?,?,?)
            """,(session_id,
            username, 
            hash_password, 
            email, 
            get_current_datetime(),))
            conn.commit()
        session["username"] = username 
        session["email"] = email
        session["session_id"] = session_id
        return jsonify({
        "success": True,
        "message": "Account Created Successfully  "
        }),201
    except Exception as e:
        app.logger.exception(e)
        return json_error("Internal server error", 500)
  
@app.route("/login/endpoint", methods=["POST"])
def login_endpoint():
    data = request.get_json() or {}
    email = data.get("email").strip().lower()
    password = data.get("password")
    if not email or not  password:
        return json_error("All fields are required ❗", 400)
    
    
    
    try:
        with get_db() as conn:
            existing = conn.execute("""
            SELECT * FROM users WHERE email = ? 
            """,(email,)).fetchone()
            if not existing:
                return json_error("invalid email or password  ❗", 400)
            if not check_password_hash(existing["hash_password"], password):
                return json_error("Invalid password or email❗", 400)
            session["session_id"] = existing["session_id"]
            session["username"] = existing["username"]
            session["email"] = existing["email"]
            session["user_id"] = existing["id"]
            
            return jsonify ({
           "success": True,
           "message": "Logged in successful ❕ "
           }),201
    except Exception as e:
            app.logger.exception(e)
            return json_error("Internal server error", 500)
  


if __name__  == "__main__":
    app.run(port=10000)