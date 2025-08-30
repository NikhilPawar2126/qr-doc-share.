import os
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import bcrypt
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
CORS(app)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), 'uploads')
USERS = os.path.join(os.path.dirname(__file__), 'users.json')
SESSIONS = os.path.join(os.path.dirname(__file__), 'sessions.json')

os.makedirs(UPLOAD_DIR, exist_ok=True)
if not os.path.exists(USERS):
    with open(USERS, 'w') as f:
        json.dump([], f)
if not os.path.exists(SESSIONS):
    with open(SESSIONS, 'w') as f:
        json.dump({}, f)

def safe_read_json(filepath, fallback):
    try:
        with open(filepath, 'r') as f:
            data = f.read().strip()
            return json.loads(data) if data else fallback
    except Exception:
        return fallback

def write_json(filepath, data):
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def write_shared_meta():
    files = [f for f in os.listdir(UPLOAD_DIR) if f.endswith('.json') and f != 'shared-meta.json']
    all_files = []
    for f in files:
        meta = safe_read_json(os.path.join(UPLOAD_DIR, f), {})
        all_files.append({
            'name': meta.get('originalName', f),
            'createdAt': meta.get('createdAt'),
            'downloadUrl': meta.get('fileUrl', '')
        })
    write_json(os.path.join(UPLOAD_DIR, 'shared-meta.json'), {'files': all_files})

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    if not all([name, email, username, password]):
        return jsonify({'error': 'All fields are required'}), 400
    users = safe_read_json(USERS, [])
    if any(u['username'] == username for u in users):
        return jsonify({'error': 'User already exists'}), 409
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users.append({'name': name, 'email': email, 'username': username, 'password': hashed})
    write_json(USERS, users)
    return jsonify({'success': True, 'message': 'Signup successful'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    users = safe_read_json(USERS, [])
    user = next((u for u in users if u['username'] == username), None)
    if not user:
        return jsonify({'error': 'Invalid username'}), 401
    if not bcrypt.checkpw(password.encode(), user['password'].encode()):
        return jsonify({'error': 'Invalid password'}), 401
    token = os.urandom(16).hex()
    sessions = safe_read_json(SESSIONS, {})
    sessions[token] = username
    write_json(SESSIONS, sessions)
    return jsonify({'success': True, 'token': token})

@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')
    sessions = safe_read_json(SESSIONS, {})
    if token and token in sessions:
        del sessions[token]
        write_json(SESSIONS, sessions)
    return jsonify({'success': True})

def auth_required(f):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')
        sessions = safe_read_json(SESSIONS, {})
        if not token or token not in sessions:
            return jsonify({'error': 'Unauthorized'}), 401
        request.username = sessions[token]
        return f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/upload', methods=['POST'])
@auth_required
def upload():
    if 'file' not in request.files or 'password' not in request.form:
        return jsonify({'error': 'Missing required fields'}), 400
    file = request.files['file']
    password = request.form['password']
    username = request.username
    doc_id = str(int.from_bytes(os.urandom(6), 'big'))
    filename = f"{doc_id}-{secure_filename(file.filename)}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    file.save(file_path)
    file_url = f"/uploads/{filename}"
    qr_page_url = f"/shared.html?docId={doc_id}"
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    meta = {
        'fileUrl': file_url,
        'passwordHash': password_hash,
        'userId': username,
        'originalName': file.filename,
        'createdAt': request.date if hasattr(request, 'date') else None
    }
    write_json(os.path.join(UPLOAD_DIR, f"{doc_id}.json"), meta)
    write_shared_meta()
    qr = qrcode.make(qr_page_url)
    buf = BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return jsonify({'qrPageUrl': qr_page_url, 'qr': f"data:image/png;base64,{qr_b64}"})

@app.route('/public/<doc_id>', methods=['GET'])
def get_public(doc_id):
    meta_path = os.path.join(UPLOAD_DIR, f"{doc_id}.json")
    if not os.path.exists(meta_path):
        return jsonify({'error': 'Not found'}), 404
    meta = safe_read_json(meta_path, {})
    meta['docId'] = doc_id
    return jsonify(meta)

@app.route('/files/<doc_id>', methods=['DELETE'])
@auth_required
def delete_file(doc_id):
    meta_path = os.path.join(UPLOAD_DIR, f"{doc_id}.json")
    if not os.path.exists(meta_path):
        return jsonify({'error': 'File not found'}), 404
    meta = safe_read_json(meta_path, {})
    if meta.get('userId') != request.username:
        return jsonify({'error': 'Forbidden'}), 403
    file_name = meta.get('fileUrl', '').split('/')[-1]
    file_path = os.path.join(UPLOAD_DIR, file_name)
    if os.path.exists(file_path):
        os.remove(file_path)
    os.remove(meta_path)
    write_shared_meta()
    return jsonify({'success': True})

@app.route('/files/<doc_id>/rename', methods=['POST'])
@auth_required
def rename_file(doc_id):
    data = request.json
    new_name = data.get('newName')
    meta_path = os.path.join(UPLOAD_DIR, f"{doc_id}.json")
    if not os.path.exists(meta_path):
        return jsonify({'error': 'File not found'}), 404
    meta = safe_read_json(meta_path, {})
    if meta.get('userId') != request.username:
        return jsonify({'error': 'Forbidden'}), 403
    meta['originalName'] = new_name
    write_json(meta_path, meta)
    write_shared_meta()
    return jsonify({'success': True})

@app.route('/files', methods=['GET'])
@auth_required
def list_files():
    files = []
    for file in os.listdir(UPLOAD_DIR):
        if file.endswith('.json') and file != 'shared-meta.json':
            meta_path = os.path.join(UPLOAD_DIR, file)
            data = safe_read_json(meta_path, {})
            doc_id = os.path.splitext(file)[0]
            if data.get('userId') == request.username:
                files.append({
                    'docId': doc_id,
                    'name': data.get('originalName', 'Unnamed File'),
                    'createdAt': data.get('createdAt'),
                    'userId': data.get('userId'),
                    'qrUrl': f"/shared.html?docId={doc_id}",
                    'downloadUrl': data.get('fileUrl', '')
                })
    return jsonify({'files': files})

@app.route('/verify-password', methods=['POST'])
def verify_password():
    data = request.json
    doc_id = data.get('docId')
    password = data.get('password')
    if not doc_id or not password:
        return jsonify({'success': False, 'error': 'docId and password required'}), 400
    meta_path = os.path.join(UPLOAD_DIR, f"{doc_id}.json")
    if not os.path.exists(meta_path):
        return jsonify({'success': False, 'error': 'File not found'}), 404
    meta = safe_read_json(meta_path, {})
    if not meta.get('passwordHash'):
        return jsonify({'success': False, 'error': 'No password hash found'}), 400
    if not bcrypt.checkpw(password.encode(), meta['passwordHash'].encode()):
        return jsonify({'success': False, 'error': 'Invalid password'}), 401
    return jsonify({'success': True})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

if __name__ == '__main__':
    app.run(port=5501, debug=True)
