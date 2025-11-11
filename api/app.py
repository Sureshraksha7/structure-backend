import os # <-- Must be present!
from flask import Flask, request, jsonify
# ... other imports
from flask_cors import CORS
import requests
import json
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager, get_jwt
from datetime import datetime, timezone, timedelta
import re 

# Vercel requires the application instance to be named 'app'
app = Flask(__name__)
CORS(app)

# --- Database and Auth Configuration ---
db_url = os.environ.get("DATABASE_URL")

# Apply Vercel/Postgres fix for SQLAlchemy 1.4+ compatibility
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# If no DATABASE_URL is set (i.e., running locally), fall back to SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = db_url or 'sqlite:///users.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# IMPORTANT: Load Secret Key from Environment Variables
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-fallback-secret-CHANGE-THIS')
app.config["JWT_BLACKLIST_ENABLED"] = True
app.config["JWT_BLACKLIST_TOKEN_CHECKS"] = ["access"] 
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1) # Set token expiry

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
# --- End of Config ---


# --- AI API Configurations (Loading from Environment) ---
# --- AI API Configurations (Loading from Environment) ---
# CRITICAL FIX: Use a safe default for local running.
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', 'local_gemini_key')
API_URL_GEMINI = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-09-2025:generateContent?key={GEMINI_API_KEY}" 

OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', 'local_openai_key')
API_URL_OPENAI = "https://api.openai.com/v1/chat/completions"
# --- End of AI Config ---

# --- Database Models (Your original models) ---
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
# --- End of Models ---


# --- VERCEL ROOT PATH FIX ---
@app.route('/')
def root_check():
    return jsonify({
        "status": "Flask API Online",
        "message": "Access endpoints like /generate, /login, or /structures.",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200
# --- END VERCEL ROOT PATH FIX ---


# --- Generator Utility Function (Your original utility function) ---
def generate_content_with_model(model_choice, company_name, category, num_pages, description, current_structure=None, refinement_prompt=None):
    
    # Define the core 3-Level JSON Schema (Unchanged)
    json_schema = {
        "type": "ARRAY",
        "items": {
            "type": "OBJECT",
            "properties": {
                "menu": {"type": "STRING", "description": "Main menu item name (Level 1)"},
                "icon": {"type": "STRING", "description": "Font Awesome 5 class (e.g., 'fas fa-home')"},
                "sections": {
                    "type": "ARRAY",
                    "items": {
                        "type": "OBJECT",
                        "properties": {
                            "section": {"type": "STRING", "description": "Section page name (Level 2)"},
                            "subsections": {
                                "type": "ARRAY",
                                "items": {
                                    "type": "OBJECT",
                                    "properties": {
                                        "name": {"type": "STRING", "description": "Name of the subsection (L3)"},
                                        "description": {"type": "STRING", "description": "1-2 sentence content description for this subsection. MUST NOT BE EMPTY."}
                                    },
                                    "required": ["name", "description"]
                                },
                                "minItems": 2,
                                "description": "NON-EMPTY array of subsection objects (Level 3)"
                            }
                        },
                        "required": ["section", "subsections"]
                    }
                }
            },
            "required": ["menu", "icon", "sections"]
        }
    }
    
    # --- 1. DETERMINE PROMPT TYPE: Initial Generation or Refinement ---
    if refinement_prompt and current_structure is not None:
        # **REFINEMENT MODE**
        current_structure_json = json.dumps(current_structure, indent=2)
        
        prompt = (
            f"You are a website structure refinement assistant. Your task is to MODIFY the provided JSON structure "
            f"for '{company_name}' based on the user's explicit request. "
            f"The current structure is:\n\n{current_structure_json}\n\n"
            f"--- User Refinement Request ---\n"
            f"'{refinement_prompt}'.\n"
            f"--- Task ---\n"
            f"Make the necessary changes. Maintain the 3-level (Menu > Section > Subsections) format and the JSON schema exactly. "
            f"If the request is complex, try to make the most logical update. Return ONLY the final, modified JSON array."
        )
        
    else:
        # **INITIAL GENERATION MODE**
        context_sentence = ""
        if description and description.strip():
            context_sentence = f"The specific context and product details are: '{description}'. "
        
        prompt = (
            f"Generate a 3-level website structure for '{company_name}' ({category}). {context_sentence}"
            f"The structure MUST be 3 levels deep: Menu > Section > Subsections. "
            f"You MUST generate EXACTLY {num_pages} 'menu' items. Do not generate more or fewer. "
            f"For each 'menu' item, provide a Font Awesome 5 'icon' class. "
            f"CRITICALLY: Every 'section' MUST have at least 2 'subsections'. "
            f"Each 'subsection' MUST be an object with a 'name' (string) and a 'description' (string, 1-2 sentences). "
            f"The 'description' MUST NOT be empty. It MUST provide a brief summary of the content for that subsection. "
            f"Return ONLY a JSON array matching this exact schema."
        )


    # --- 2. API Call Logic ---
    if model_choice == 'openai':
        # --- OpenAI API Call Logic ---
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}"
        }
        
        system_content = "You are a JSON structure generator. You MUST follow the user's schema exactly. CRITICALLY: 'subsections' arrays must NOT be empty and must contain at least 2 objects, each with a 'name' and a non-empty 'description'. You MUST return ONLY the raw JSON array."
        if refinement_prompt:
            system_content = "You are a website structure refinement assistant. You MUST modify the provided JSON structure based on the request and return the complete, revised JSON array that strictly adheres to the schema (Menu > Section > Subsections, subsections must have a 'name' and non-empty 'description')."
            
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": prompt} 
            ],
            "response_format": {"type": "json_object"}, 
            "temperature": 0.5
        }
        response = requests.post(API_URL_OPENAI, headers=headers, data=json.dumps(payload))
        
        if response.status_code != 200:
            raise Exception(f"OpenAI API Error ({response.status_code}): {response.text}")
            
        result = response.json()
        json_text = result['choices'][0]['message']['content']
        
    else: # Default to gemini
        # --- Gemini API Call Logic ---
        payload = { 
            "contents": [{"parts": [{"text": prompt}]}], 
            "generationConfig": { 
                "responseMimeType": "application/json", 
                "responseSchema": json_schema
            } 
        }
        headers = {"Content-Type": "application/json"}
        response = requests.post(API_URL_GEMINI, headers=headers, data=json.dumps(payload))

        if response.status_code != 200:
            raise Exception(f"Gemini API Error ({response.status_code}): {response.text}")

        result = response.json()
        json_text = result['candidates'][0]['content']['parts'][0]['text']
    
    return json_text
# --- End of Generator Utility Function ---


# --- Generator Routes (Your original routes) ---
@app.route('/generate', methods=['POST'])
@jwt_required() 
def generate_structure():
    user_id_str = get_jwt_identity() 
    current_user_id = int(user_id_str) 
    
    try:
        data = request.get_json()
        company_name = data.get('company_name', 'Company')
        category = data.get('category', 'General')
        num_pages = data.get('num_pages', 5)
        description = data.get('description', '') 
        model_choice = data.get('model', 'gemini')

        raw_json_text = generate_content_with_model(
            model_choice=model_choice,
            company_name=company_name, 
            category=category, 
            num_pages=num_pages, 
            description=description,
            current_structure=None,
            refinement_prompt=None
        )
        
        match = re.search(r'\[.*\]', raw_json_text, re.DOTALL)
        
        if match:
            cleaned_json_text = match.group(0).strip()
        else:
            cleaned_json_text = raw_json_text.strip()
            
        new_structure = Structure(
            company_name=company_name,
            category=category,
            json_data=cleaned_json_text,
            user_id=current_user_id,
            model_used=model_choice
        )
        db.session.add(new_structure)
        db.session.commit()

        return jsonify(new_structure.to_dict()), 201 

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/structures/refine/<int:structure_id>', methods=['POST'])
@jwt_required()
def refine_structure(structure_id):
    user_id_str = get_jwt_identity()
    current_user_id = int(user_id_str)

    structure = Structure.query.get(structure_id)

    if not structure:
        return jsonify({"error": "Structure not found"}), 404
        
    if structure.user_id != current_user_id: 
        return jsonify({"error": "Unauthorized"}), 403 

    try:
        data = request.get_json()
        current_structure = data.get('current_structure')
        refinement_prompt = data.get('refinement_prompt')
        company_name = data.get('company_name', structure.company_name)
        model_choice = structure.model_used

        if not current_structure or not refinement_prompt:
             return jsonify({"error": "Missing current_structure or refinement_prompt"}), 400

        refined_json_text = generate_content_with_model(
            model_choice=model_choice,
            company_name=company_name,
            category=structure.category,
            num_pages=0,
            description="",
            current_structure=current_structure,
            refinement_prompt=refinement_prompt
        )

        match = re.search(r'\[.*\]', refined_json_text, re.DOTALL)
        if match:
            cleaned_json_text = match.group(0).strip()
        else:
            cleaned_json_text = refined_json_text.strip()

        structure.json_data = cleaned_json_text
        structure.company_name = company_name
        db.session.commit()

        return jsonify(structure.to_dict()), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/structures', methods=['GET'])
@jwt_required()
def get_structures():
    user_id_str = get_jwt_identity()
    current_user_id = int(user_id_str) 
    user = User.query.get(current_user_id) 
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    structures = [s.to_dict() for s in user.structures]
    
    return jsonify(structures), 200

@app.route('/structures/<int:structure_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required()
def handle_structure(structure_id):
    user_id_str = get_jwt_identity()
    current_user_id = int(user_id_str) 
    
    structure = Structure.query.get(structure_id)
    
    if not structure:
        return jsonify({"error": "Structure not found"}), 404
        
    if structure.user_id != current_user_id: 
        return jsonify({"error": "Unauthorized"}), 403 

    if request.method == 'GET':
        return jsonify(structure.to_dict()), 200
        
    if request.method == 'PUT':
        try:
            data = request.get_json()
            
            if 'company_name' in data:
                structure.company_name = data['company_name']
                
            if 'structure' in data:
                structure.json_data = json.dumps(data['structure'])
                
            db.session.commit()
            return jsonify({"message": "Structure updated successfully"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

    if request.method == 'DELETE':
        try:
            db.session.delete(structure)
            db.session.commit()
            return jsonify({"message": "Structure deleted successfully"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

# --- Auth Routes ---
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
    
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": f"User {email} registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=str(user.id)) 
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/profile', methods=['GET', 'PUT'])
@jwt_required()
def profile():
    user_id_str = get_jwt_identity() 
    user = User.query.get(int(user_id_str)) 
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    if request.method == 'GET':
        return jsonify({
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone or ""
        }), 200

    if request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            user.name = data['name']
        
        if 'phone' in data:
            user.phone = data['phone']
            
        if 'email' in data and data['email'] != user.email:
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                return jsonify({"error": "Email already in use"}), 400
            user.email = data['email']
            
        try:
            db.session.commit()
            return jsonify({"message": "Profile updated successfully"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e)}), 500

@app.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    user_id_str = get_jwt_identity()
    user = User.query.get(int(user_id_str))
    
    if not user:
        return jsonify({"error": "User not found"}), 404
        
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    if not old_password or not new_password:
        return jsonify({"error": "Old and new passwords are required"}), 400
        
    if not bcrypt.check_password_hash(user.password_hash, old_password):
        return jsonify({"error": "Invalid old password"}), 401
        
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password_hash = hashed_password
    
    try:
        db.session.commit()
        return jsonify({"message": "Password updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    try:
        jti = get_jwt()["jti"]
        blacklisted_token = TokenBlacklist(jti=jti)
        db.session.add(blacklisted_token)
        db.session.commit()
        return jsonify({"message": "Successfully logged out"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)

# --- END VERCEL/LOCAL EXECUTION BLOCK ---