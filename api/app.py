import os  # <-- Must be present!
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import json
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager, get_jwt
from datetime import datetime, timezone, timedelta
import re

# --- Flask App Initialization ---
app = Flask(__name__)

# ✅ Allow frontend hosted on Vercel to access backend API
CORS(app, origins=[
    "https://vercel-frontend.vercel.app",  # Replace with your actual frontend URL
    "http://localhost:3000"  # For local development
], supports_credentials=True)

# --- Database and Auth Configuration ---
db_url = os.environ.get("DATABASE_URL")

# Fix for Render Postgres URL format
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Fallback to SQLite for local use
app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT Config
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-fallback-secret-CHANGE-THIS')
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- AI API Configurations ---
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

    def __repr__(self):
        return f'<User {self.email}>'


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


# --- Health Check Route ---
@app.route('/')
def root_check():
    return jsonify({
        "status": "Flask API Online ✅",
        "message": "Access endpoints like /generate, /login, or /structures.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200


# --- Generator Function (AI Integration) ---
def generate_content_with_model(model_choice, company_name, category, num_pages, description, current_structure=None, refinement_prompt=None):
    json_schema = {
        "type": "ARRAY",
        "items": {
            "type": "OBJECT",
            "properties": {
                "menu": {"type": "STRING"},
                "icon": {"type": "STRING"},
                "sections": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "section": {"type": "STRING"},
                            "subsections": {
                                "type": "ARRAY",
                                "items": {
                                    "type": "OBJECT",
                                    "properties": {
                                        "name": {"type": "STRING"},
                                        "description": {"type": "STRING"}
                                    },
                                    "required": ["name", "description"]
                                },
                                "minItems": 2
                            }
                        },
                        "required": ["section", "subsections"]
                    }
                }
            },
            "required": ["menu", "icon", "sections"]
        }
    }

    if refinement_prompt and current_structure is not None:
        current_structure_json = json.dumps(current_structure, indent=2)
        prompt = (
            f"Refine the provided JSON structure for '{company_name}' based on this request: '{refinement_prompt}'. "
            f"Current structure:\n{current_structure_json}"
        )
    else:
        context_sentence = f"The specific context is: '{description}'." if description else ""
        prompt = (
            f"Generate a 3-level website structure for '{company_name}' ({category}). {context_sentence} "
            f"Must have {num_pages} menu items, each with sections and at least 2 subsections."
        )

    if model_choice == 'openai':
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You must return valid JSON strictly matching the schema."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.5
        }
        response = requests.post(API_URL_OPENAI, headers=headers, data=json.dumps(payload))
        result = response.json()
        json_text = result['choices'][0]['message']['content']
    else:
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json", "responseSchema": json_schema}
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(API_URL_GEMINI, headers=headers, data=json.dumps(payload))
        result = response.json()
        json_text = result['candidates'][0]['content']['parts'][0]['text']

    return json_text


# --- ROUTES (Auth + Structure Handling) ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    phone = data.get('phone')
    if not email or not password or not name:
        return jsonify({"error": "Name, email, and password are required"}), 400
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Email already registered"}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, phone=phone, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": f"User {email} registered successfully"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token), 200
    return jsonify({"error": "Invalid credentials"}), 401


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    db.session.add(TokenBlacklist(jti=jti))
    db.session.commit()
    return jsonify({"message": "Logged out successfully"}), 200


# --- Run Flask ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
