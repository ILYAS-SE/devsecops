from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import re

app = Flask(__name__)

def validate_input(username, password):
    """Valide les entrées utilisateur"""
    if not username or not password:
        return False
    
    # Username: alphanumerique uniquement, 3-20 caractères
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return False
    
    # Password: minimum 8 caractères
    if len(password) < 8:
        return False
    
    return True

@app.route("/login", methods=["POST"])
def login():
    try:
        # Récupération des données
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid request"}), 400
        
        username = data.get("username", "")
        password = data.get("password", "")
        
        # Validation des entrées
        if not validate_input(username, password):
            return jsonify({"status": "error", "message": "Invalid input"}), 400
        
        # Connexion à la base de données
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        # Requête paramétrée (protection contre SQL injection)
        query = "SELECT username, password_hash FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        
        conn.close()
        
        # Vérification du mot de passe avec bcrypt
        if result and bcrypt.checkpw(password.encode('utf-8'), result[1].encode('utf-8')):
            return jsonify({"status": "success", "user": result[0]}), 200
        
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        
    except sqlite3.Error as e:
        return jsonify({"status": "error", "message": "Database error"}), 500
    except Exception as e:
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/health", methods=["GET"])
def health():
    """Endpoint de santé"""
    return jsonify({"status": "healthy"}), 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=False)