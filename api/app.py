from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
import datetime
import logging

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///structure.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key'

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ✅ Proper full CORS setup for Vercel + local development
CORS(app, resources={r"/*": {
    "origins": [
        "https://vercel-frontend-kappa-bice.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:5500"
    ],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "Authorization"]
}}, supports_credentials=True)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('app')

# --------------------- MODELS --------------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password = db.Column(db.String(200), nullable=False)

class Structure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(150), nullable=False)
    project_description = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class TokenBlacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), nullable=False)

# --------------------- ROUTES --------------------- #

# Health check (to test backend + CORS quickly)
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "Backend running successfully 🚀"}), 200

# Register user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    password = data.get('password')

    if not all([name, email, password]):
        return jsonify({"error": "Missing required fields"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "User already exists"}), 409

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, phone=phone, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": f"User {email} registered successfully"}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid email or password"}), 401

    access_token = create_access_token(
        identity=email, expires_delta=datetime.timedelta(hours=2)
    )
    return jsonify({"access_token": access_token}), 200

# Profile route
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "name": user.name,
        "email": user.email,
        "phone": user.phone
    }), 200

# Structures route
@app.route('/structures', methods=['GET'])
@jwt_required()
def get_structures():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    structures = Structure.query.filter_by(user_id=user.id).all()
    result = [
        {
            "id": s.id,
            "company_name": s.company_name,
            "project_description": s.project_description
        } for s in structures
    ]
    return jsonify(result), 200

# Add new structure
@app.route('/structures', methods=['POST'])
@jwt_required()
def add_structure():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    data = request.get_json()
    company_name = data.get('company_name')
    project_description = data.get('project_description')

    if not company_name:
        return jsonify({"error": "Company name is required"}), 400

    new_structure = Structure(
        company_name=company_name,
        project_description=project_description,
        user_id=user.id
    )
    db.session.add(new_structure)
    db.session.commit()

    return jsonify({"message": "Structure added successfully"}), 201

# Logout route
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt_identity()
    blacklisted = TokenBlacklist(jti=jti)
    db.session.add(blacklisted)
    db.session.commit()
    return jsonify({"message": "Successfully logged out"}), 200

# --------------------- MAIN --------------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully ✅")

    app.run(host='0.0.0.0', port=5000)
