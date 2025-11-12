from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
import logging

app = Flask(__name__)

# ================== CONFIGURATION ==================
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///project.db"
).replace("postgres://", "postgresql://")  # Fix for Render PostgreSQL URLs
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "your_secret_key")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Allow CORS between your backend (Render) and frontend (Vercel)
CORS(app, supports_credentials=True, origins=[
    "https://vercel-frontend-kappa-bice.vercel.app",  # your Vercel domain
    "http://localhost:3000"  # for local testing
])

# ================== LOGGER SETUP ==================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

# ================== DATABASE MODELS ==================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(128), nullable=False)

    def __init__(self, name, email, password_hash, phone=None):
        self.name = name
        self.email = email
        self.password_hash = password_hash
        self.phone = phone


class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(500), nullable=False)

# ================== ROUTES ==================

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        phone = data.get("phone")

        if not all([name, email, password]):
            return jsonify({"error": "Missing required fields"}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({"error": "Email already registered"}), 400

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(name=name, email=email, password_hash=hashed_pw, phone=phone)
        db.session.add(new_user)
        db.session.commit()

        return jsonify({"message": f"User {email} registered successfully"}), 201

    except Exception as e:
        logger.error(f"Error during registration: {e}")
        return jsonify({"error": "Internal server error occurred during registration"}), 500


@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not all([email, password]):
            return jsonify({"error": "Missing email or password"}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not bcrypt.check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid credentials"}), 401

        return jsonify({"message": "Login successful", "user_id": user.id, "email": user.email}), 200

    except Exception as e:
        logger.error(f"Error during login: {e}")
        return jsonify({"error": "Internal server error occurred during login"}), 500


@app.route("/profile", methods=["GET"])
def profile():
    try:
        users = User.query.all()
        if not users:
            return jsonify({"message": "No users found"}), 404

        user_list = [
            {"id": u.id, "name": u.name, "email": u.email, "phone": u.phone}
            for u in users
        ]
        return jsonify(user_list), 200
    except Exception as e:
        logger.error(f"Error fetching profile: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/structures", methods=["GET"])
def get_structures():
    try:
        structures = Structure.query.all()
        if not structures:
            return jsonify({"message": "No structures found"}), 404

        structure_list = [
            {"id": s.id, "company_name": s.company_name, "user_id": s.user_id}
            for s in structures
        ]
        return jsonify(structure_list), 200
    except Exception as e:
        logger.error(f"Error fetching structures: {e}")
        return jsonify({"error": "Internal server error"}), 500


# ================== APP ENTRY POINT ==================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully ✅")

    port = int(os.environ.get("PORT", 5000))  # required for Render
    app.run(host="0.0.0.0", port=port)
