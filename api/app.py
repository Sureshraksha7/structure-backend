from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)

# Allow only your frontend origin explicitly
CORS(app, resources={r"/*": {"origins": ["https://vercel-frontend-kappa-bice.vercel.app"]}}, supports_credentials=True)

# Ensure OPTIONS requests are handled correctly
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', 'https://vercel-frontend-kappa-bice.vercel.app')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# Handle root route
@app.route('/')
def home():
    return jsonify({"message": "Backend is running successfully!"})

# Example profile endpoint
@app.route('/profile', methods=['GET', 'OPTIONS'])
def get_profile():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'OK'}), 200
    profile_data = {
        "name": "Raksha",
        "role": "AIML Engineer",
        "email": "raksha@example.com"
    }
    return jsonify(profile_data)

# Example structures endpoint
@app.route('/structures', methods=['GET', 'OPTIONS'])
def get_structures():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'OK'}), 200
    structures = [
        {"id": 1, "name": "AI Chatbot", "status": "Completed"},
        {"id": 2, "name": "Voice Interaction Module", "status": "In Progress"}
    ]
    return jsonify(structures)

# Example POST endpoint
@app.route('/add', methods=['POST', 'OPTIONS'])
def add_structure():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'OK'}), 200
    data = request.get_json()
    print("Received data:", data)
    return jsonify({"message": "Data received successfully", "data": data}), 201

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
