from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import re
import os
from pathlib import Path

app = Flask(__name__)

# Secret chargé depuis variable d'environnement
SECRET_KEY = os.environ.get('SECRET_KEY', None)
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable must be set")

ALLOWED_FILES_DIR = Path("/app/data")

def validate_username(username):
    """Valide le format du username"""
    if not username or not isinstance(username, str):
        return False
    # Alphanumerique uniquement, 3-20 caractères
    return bool(re.match(r'^[a-zA-Z0-9_]{3,20}$', username))

def validate_password(password):
    """Valide le format du password"""
    if not password or not isinstance(password, str):
        return False
    # Minimum 8 caractères
    return len(password) >= 8

def validate_host(host):
    """Valide le format d'un hostname/IP"""
    if not host or not isinstance(host, str):
        return False
    # IP ou hostname valide
    return bool(re.match(r'^[a-zA-Z0-9\.\-]{1,255}$', host))

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid request"}), 400
        
        username = data.get("username", "")
        password = data.get("password", "")
        
        # Validation des entrées
        if not validate_username(username) or not validate_password(password):
            return jsonify({"status": "error", "message": "Invalid input"}), 400
        
        # Connexion sécurisée
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        
        # Requête paramétrée (protection SQL injection)
        query = "SELECT username, password_hash FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        conn.close()
        
        # Vérification bcrypt
        if result and bcrypt.checkpw(password.encode('utf-8'), result[1].encode('utf-8')):
            return jsonify({"status": "success", "user": result[0]}), 200
        
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        
    except sqlite3.Error:
        return jsonify({"status": "error", "message": "Database error"}), 500
    except Exception:
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/ping", methods=["POST"])
def ping():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid request"}), 400
        
        host = data.get("host", "")
        
        # Validation stricte
        if not validate_host(host):
            return jsonify({"status": "error", "message": "Invalid host"}), 400
        
        # Utilisation sécurisée (pas de shell=True)
        import subprocess
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return jsonify({"output": result.stdout}), 200
        
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Timeout"}), 408
    except Exception:
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/compute", methods=["POST"])
def compute():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid request"}), 400
        
        expression = data.get("expression", "")
        
        # Validation stricte - seulement chiffres et opérateurs basiques
        if not re.match(r'^[\d\+\-\*\/\(\)\s\.]+$', expression):
            return jsonify({"status": "error", "message": "Invalid expression"}), 400
        
        # Utilisation sécurisée avec ast.literal_eval (pas eval())
        import ast
        import operator
        
        # Parse sécurisé
        ops = {
            ast.Add: operator.add,
            ast.Sub: operator.sub,
            ast.Mult: operator.mul,
            ast.Div: operator.truediv
        }
        
        def safe_eval(node):
            if isinstance(node, ast.Num):
                return node.n
            elif isinstance(node, ast.BinOp):
                return ops[type(node.op)](safe_eval(node.left), safe_eval(node.right))
            else:
                raise ValueError("Invalid expression")
        
        tree = ast.parse(expression, mode='eval')
        result = safe_eval(tree.body)
        
        return jsonify({"result": result}), 200
        
    except Exception:
        return jsonify({"status": "error", "message": "Invalid expression"}), 400

@app.route("/hash", methods=["POST"])
def hash_password():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid request"}), 400
        
        pwd = data.get("password", "")
        
        if not validate_password(pwd):
            return jsonify({"status": "error", "message": "Invalid password"}), 400
        
        # Utilisation de bcrypt (pas MD5)
        hashed = bcrypt.hashpw(pwd.encode('utf-8'), bcrypt.gensalt())
        
        return jsonify({"bcrypt_hash": hashed.decode('utf-8')}), 200
        
    except Exception:
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/readfile", methods=["POST"])
def readfile():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid request"}), 400
        
        filename = data.get("filename", "")
        
        # Validation du nom de fichier
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
            return jsonify({"status": "error", "message": "Invalid filename"}), 400
        
        # Protection contre path traversal
        file_path = (ALLOWED_FILES_DIR / filename).resolve()
        
        # Vérifier que le fichier est bien dans le répertoire autorisé
        if not str(file_path).startswith(str(ALLOWED_FILES_DIR)):
            return jsonify({"status": "error", "message": "Access denied"}), 403
        
        if not file_path.exists():
            return jsonify({"status": "error", "message": "File not found"}), 404
        
        with open(file_path, "r") as f:
            content = f.read()
        
        return jsonify({"content": content}), 200
        
    except Exception:
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/health", methods=["GET"])
def health():
    """Endpoint de santé (pas de debug info)"""
    return jsonify({"status": "healthy"}), 200

@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the DevSecOps secure API"}), 200

if __name__ == "__main__":
    # Debug désactivé en production
    app.run(host="0.0.0.0", port=5000, debug=False)