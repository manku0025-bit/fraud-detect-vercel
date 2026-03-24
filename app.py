from flask import Flask, render_template, request, redirect, session, flash, url_for, send_file
import pandas as pd
import sqlite3
import pickle
import os
import cv2
import pytesseract
import random
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "fraud_ai_secret"

# ===============================
# 🔥 LOAD FRAUD MODELS
# ===============================
model_files = [
    "creditcard_model.pkl",
    "test_model.pkl",
    "Fraud_Data_model.pkl"
]

fraud_models = []

for f in model_files:
    if os.path.exists(f):
        model, features = pickle.load(open(f, "rb"))
        fraud_models.append((model, features, f))

# ===============================
# 🔥 LOAD SCAM MODEL
# ===============================
scam_model, vectorizer = pickle.load(open("scam_model.pkl", "rb"))

# ===============================
# CREATE UPLOAD FOLDER
# ===============================
if not os.path.exists("uploads"):
    os.makedirs("uploads")

# ===============================
# DATABASE HELPER
# ===============================
def get_db():
    con = sqlite3.connect("users.db")
    con.row_factory = sqlite3.Row
    return con

# ===============================
# AUTO MODEL DETECTION
# ===============================
def detect_best_model(df):
    best_model = None
    best_features = None
    max_match = 0

    for model, features, name in fraud_models:
        match = len(set(features).intersection(df.columns))
        if match > max_match:
            max_match = match
            best_model = model
            best_features = features

    return best_model, best_features

# ===============================
# FRAUD EXPLANATION
# ===============================
def explain_fraud(row):
    reasons = []

    if "amount" in row and row["amount"] > 10000:
        reasons.append("High transaction amount")

    if "oldbalanceOrg" in row and row["oldbalanceOrg"] == 0:
        reasons.append("Zero sender balance")

    if "newbalanceOrig" in row and row["newbalanceOrig"] == 0:
        reasons.append("Balance emptied")

    return ", ".join(reasons) if reasons else "Normal behavior"

# ===============================
# LOGIN
# ===============================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user"] = user["fullname"]
            session["email"] = user["email"]
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid Username or Password")

    return render_template("login.html")

# ===============================
# REGISTER
# ===============================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        mobile = request.form['mobile']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash("Passwords do not match!")
            return render_template('register.html')

        if not re.fullmatch(r'[0-9]{10}', mobile):
            flash("Invalid mobile number!")
            return render_template('register.html')

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email=? OR mobile=?",
            (email, mobile)
        ).fetchone()

        if user:
            flash("User already exists!")
            return render_template('register.html')

        hashed = generate_password_hash(password)

        db.execute(
            "INSERT INTO users (fullname, email, mobile, password) VALUES (?, ?, ?, ?)",
            (fullname, email, mobile, hashed)
        )
        db.commit()

        flash("Registration Successful!")
        return redirect(url_for('login'))

    return render_template('register.html')

# ===============================
# FORGOT PASSWORD
# ===============================
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

        if not user:
            flash("Email not registered")
            return render_template("forgot.html")

        otp = str(random.randint(1000, 9999))
        session["reset_otp"] = otp
        session["reset_email"] = email

        print("OTP:", otp)
        flash("OTP sent! Check terminal")

        return redirect(url_for("reset_password"))

    return render_template("forgot.html")

# ===============================
# RESET PASSWORD
# ===============================
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        otp = request.form["otp"]
        new_password = request.form["new_password"]

        if otp != session.get("reset_otp"):
            flash("Invalid OTP")
            return render_template("reset.html")

        hashed = generate_password_hash(new_password)

        db = get_db()
        db.execute(
            "UPDATE users SET password=? WHERE email=?",
            (hashed, session["reset_email"])
        )
        db.commit()

        session.pop("reset_otp", None)
        session.pop("reset_email", None)

        flash("Password updated successfully")
        return redirect(url_for("login"))

    return render_template("reset.html")

# ===============================
# DASHBOARD
# ===============================
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    safe = medium = high = 0
    results = None

    if request.method == "POST":
        csv_file = request.files.get("file")
        image_file = request.files.get("image")
        message = request.form.get("message")

        # =========================
        # CSV PROCESSING
        # =========================
        if csv_file and csv_file.filename:
            os.makedirs("uploads", exist_ok=True)
            path = os.path.join("uploads", csv_file.filename)
            csv_file.save(path)

            df = pd.read_csv(path)
            model, features = detect_best_model(df)

            if model is None:
                flash("No suitable model")
                return redirect(url_for("dashboard"))

            if "Class" in df.columns:
                df = df.drop("Class", axis=1)

            df_input = df.reindex(columns=features, fill_value=0)
            probs = model.predict_proba(df_input)

            df_input["Fraud_Score"] = probs[:, 1]
            df_input["Risk_Level"] = df_input["Fraud_Score"].apply(
                lambda x: "HIGH" if x > 0.59 else "MEDIUM" if x > 0.5 else "LOW"
            )

            safe = len(df_input[df_input["Risk_Level"] == "LOW"])
            medium = len(df_input[df_input["Risk_Level"] == "MEDIUM"])
            high = len(df_input[df_input["Risk_Level"] == "HIGH"])

            results = df_input.head(10).to_dict(orient="records")
            session["last_results"] = results

        # =========================
        # IMAGE PROCESSING
        # =========================
        elif image_file and image_file.filename:
            os.makedirs("uploads", exist_ok=True)
            path = os.path.join("uploads", image_file.filename)
            image_file.save(path)

            try:
                import numpy as np

                image_file.seek(0)
                file_bytes = np.frombuffer(image_file.read(), np.uint8)
                img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

                if img is None:
                    img = cv2.imread(path)

                if img is None:
                    flash("❌ Could not read image")
                    return redirect(url_for("dashboard"))

                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                gray = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY)[1]

                text = pytesseract.image_to_string(gray)
                X = vectorizer.transform([text])
                prob = scam_model.predict_proba(X)[0][1]

                # ✅ FIX: update dashboard counters
                if prob > 0.59:
                    high = 1
                    risk_label = "HIGH"
                elif prob > 0.5:
                    medium = 1
                    risk_label = "MEDIUM"
                else:
                    safe = 1
                    risk_label = "LOW"
    
                result_text = "⚠ Fraud Text Found" if prob > 0.59 else "✅ Safe"

                results = [{
                    "Type": "Image",
                    "Extracted_Text": text,
                    "Result": result_text,
                    "Risk": risk_label,
                    "Score": round(prob * 100, 2)
                }]

                session["last_results"] = results

            except Exception as e:
                print("Image error:", e)
                flash("❌ Error processing image")
                return redirect(url_for("dashboard"))

        # =========================
        # MESSAGE PROCESSING
        # =========================
        elif message:
            X = vectorizer.transform([message])
            prob = scam_model.predict_proba(X)[0][1]

            if prob > 0.59:
                high = 1
                risk = "HIGH"
            elif prob > 0.5:
                medium = 1
                risk = "MEDIUM"
            else:
                safe = 1
                risk = "LOW"

            result_text = "⚠ Scam Message" if prob > 0.59 else "✅ Safe Message"

            results = [{
                "Type": "Message",
                "Content": message,
                "Result": result_text,
                "Risk": risk,
                "Score": round(prob * 100, 2)
            }]

            session["last_results"] = results

    return render_template(
        "dashboard.html",
        safe=safe,
        medium=medium,
        high=high,
        results=results
    )
# ===============================
# DOWNLOAD REPORT
# ===============================
@app.route("/download", methods=["POST"])
def download():
    if "last_results" not in session:
        return redirect(url_for("dashboard"))

    df = pd.DataFrame(session["last_results"])
    file_path = "report.csv"
    df.to_csv(file_path, index=False)

    return send_file(file_path, as_attachment=True)

# ===============================
# LOGOUT
# ===============================
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ===============================
# RUN
# ===============================
def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT,
            email TEXT UNIQUE,
            mobile TEXT,
            password TEXT
        )
    """)
    db.commit()
    db.close()

# Call it ALWAYS (important for Render)
init_db()

if __name__ == "__main__":
    app.run(debug=True)
