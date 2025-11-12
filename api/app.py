import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import logging

app = Flask(__name__)

# --- Logging setup ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("flask-app")

# --- Database Config ---
db_url = os.environ.get("DATABASE_URL", "sqlite:///data.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://")

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "your_secret_key")

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- CORS Config (critical fix) ---
CORS(
    app,
    resources={r"/*": {"origins": [
        "https://vercel-frontend-kappa-bice.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:5500"
    ]}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]
)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(128), nullable=False)

class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(120), nullable=False)
    category = db.Column(db.String(120))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

# --- Utility: ensure preflight OPTIONS always succeeds ---
@app.before_request
def handle_options_preflight():
    if request.method == "OPTIONS":
        response = app.make_default_options_response()
        headers = response.headers
        headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "")
        headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        headers["Access-Control-Allow-Credentials"] = "true"
        return response, 200

# --- Routes ---
@app.route("/")
def home():
    return jsonify({"message": "Backend is running fine ✅"}), 200

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    phone = data.get("phone")

    if not name or not email or not password:
        return jsonify({"error": "Name, email and password are required"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(name=name, email=email, phone=phone, password_hash=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": f"User {email} registered successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({
        "message": "Login successful",
        "user_id": user.id,
        "email": user.email,
        "name": user.name
    }), 200

@app.route("/profile", methods=["GET"])
def profile():
    users = User.query.all()
    if not users:
        return jsonify({"message": "No users found"}), 404

    user_list = [
        {"id": u.id, "name": u.name, "email": u.email, "phone": u.phone}
        for u in users
    ]
    return jsonify(user_list), 200

@app.route("/structures", methods=["GET"])
def structures():
    structures = Structure.query.all()
    if not structures:
        return jsonify({"message": "No structures found"}), 404

    data = [
        {"id": s.id, "company_name": s.company_name, "category": s.category}
        for s in structures
    ]
    return jsonify(data), 200

# --- Start the app ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully ✅")

    port = int(os.environ.get("PORT", 10000))  # Important for Render
    app.run(host="0.0.0.0", port=port)
