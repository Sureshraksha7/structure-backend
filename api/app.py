import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token, jwt_required, get_jwt_identity,
    JWTManager, get_jwt
)
from datetime import datetime, timezone, timedelta
import logging
from functools import wraps

# --- Logging ---
logging.basicConfig(level=logging.INFO)

# --- Flask App Setup ---
app = Flask(__name__)

# ✅ Proper CORS setup for Render + Vercel + Local testing
CORS(app, resources={r"/*": {
    "origins": [
        "https://vercel-frontend-kappa-bice.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:5500"
    ],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"],
    "expose_headers": ["Content-Type", "Authorization"],
    "supports_credentials": True
}})

# --- Database Setup ---
db_url = os.environ.get("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- JWT Config ---
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-fallback-secret')
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- AI API Config ---
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'local_gemini_key')
API_URL_GEMINI = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={GEMINI_API_KEY}"

OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', 'local_openai_key')
API_URL_OPENAI = "https://api.openai.com/v1/chat/completions"

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)
    structures = db.relationship('Structure', backref='user', lazy=True, cascade="all, delete-orphan")

class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    json_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    model_used = db.Column(db.String(50), nullable=True, default='gemini')

    def to_dict(self):
        structure_json = json.loads(self.json_data)
        num_pages = len(structure_json)
        return {
            "id": self.id,
            "company_name": self.company_name,
            "category": self.category,
            "structure": structure_json,
            "created_at": self.created_at.isoformat(),
            "user_id": self.user_id,
            "num_pages": num_pages,
            "model_used": self.model_used
        }

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None

# --- JWT Optional Decorator for OPTIONS ---
def jwt_optional_for_options(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if request.method == 'OPTIONS':
            return jsonify({}), 200
        return fn(*args, **kwargs)
    return wrapper

# --- Health Check ---
@app.route('/health')
def health():
    return jsonify({
        "status": "Backend running successfully 🚀",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

# --- Register User ---
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email, password, name, phone = data.get('email'), data.get('password'), data.get('name'), data.get('phone')
        if not email or not password or not name:
            return jsonify({"error": "Name, email, and password are required"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, phone=phone, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": f"User {email} registered successfully"}), 201
    except Exception as e:
        app.logger.error(f"Error in /register: {e}", exc_info=True)
        return jsonify({"error": "Internal server error occurred during registration"}), 500

# --- Login ---
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email, password = data.get('email'), data.get('password')
        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            access_token = create_access_token(identity=str(user.id))
            return jsonify(access_token=access_token), 200
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        app.logger.error(f"Error in /login: {e}", exc_info=True)
        return jsonify({"error": "Internal server error occurred during login"}), 500

# --- Logout ---
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()["jti"]
        db.session.add(TokenBlacklist(jti=jti))
        db.session.commit()
        return jsonify({"message": "Logged out successfully"}), 200
    except Exception as e:
        app.logger.error(f"Error in /logout: {e}", exc_info=True)
        return jsonify({"error": "Internal server error occurred during logout"}), 500

# --- Profile ---
@app.route('/profile', methods=['GET', 'OPTIONS'])
@jwt_optional_for_options
@jwt_required()
def profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "phone": user.phone
    }), 200

# --- Structures ---
@app.route('/structures', methods=['GET', 'OPTIONS'])
@jwt_optional_for_options
@jwt_required()
def structures():
    current_user_id = get_jwt_identity()
    structures = Structure.query.filter_by(user_id=current_user_id).all()
    return jsonify([s.to_dict() for s in structures]), 200

# --- Fix CORS for all responses ---
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'https://vercel-frontend-kappa-bice.vercel.app')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# --- Run Flask ---
if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            app.logger.info("Database tables created successfully ✅")
        except Exception as e:
            app.logger.error(f"Error creating database tables: {e}", exc_info=True)

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
