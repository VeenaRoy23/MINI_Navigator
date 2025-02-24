from flask import Flask, jsonify, render_template, request, redirect, url_for, session, flash
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/MINI_NAVIGATOR"
mongo = PyMongo(app)

# Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Secret key for session management
app.secret_key = "your_secret_key"

# Flask-Mail Configuration (Using Environment Variables)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

mail = Mail(app)

# ------------------ ROUTES ------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/upload_materials_page")
def upload_materials_page():
    return render_template("upload_materials_page.html")

@app.route("/educator_signup_page")
def educator_signup_page():
    return render_template("educator_signup_page.html")

@app.route("/login_page")
def login_page():
    return render_template("login_page.html")

# ------------------ STUDENT AUTH ------------------

@app.route("/student_login", methods=["GET","POST"])
def student_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        student = mongo.db.students.find_one({"username": username})  # ✅ Fixed

        if student:
            stored_password = student["password"]
            if bcrypt.check_password_hash(stored_password, password):
                flash("Login Success.", "success")
                return render_template("select_stream.html")
            else:
                return "Invalid Password"
        else:
            return "Username Not Found"

    return render_template("student_login.html")

@app.route("/student_signup", methods=["GET", "POST"])
def student_signup():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"]
        dob = request.form["dob"]
        gender = request.form["gender"]
        username = request.form["username"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("student_signup"))

        existing_user = mongo.db.students.find_one({"$or": [{"username": username}, {"email": email}]})
        if existing_user:
            flash("Username or Email already exists!", "warning")
            return redirect(url_for("student_signup"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        student_data = {
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "dob": dob,
            "gender": gender,
            "username": username,
            "password": hashed_password
        }

        mongo.db.students.insert_one(student_data)
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("student_login"))

    return render_template("student_signup.html")

# File Upload Configuration
UPLOAD_FOLDER = "uploads/"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/educator_signup", methods=["GET","POST"])
def educator_signup():
    try:
        print(request.form)  # Debugging: Print form data
        print(request.files)
        
        fullname = request.form.get("fullname")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm-password")
        gender = request.form.get("gender")
        qualification = request.form.get("qualification")
        certificate = request.files.get("certificate")

        # Validation
        if not fullname or not email or not password or not confirm_password or not gender or not qualification:
            return jsonify({"error": "All fields are required"}), 400
        if password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400
        if mongo.db.educators.find_one({"email": email}):
            return jsonify({"error": "Email already exists"}), 400

        # Hash Password
        hashed_password = generate_password_hash(password)

        # Save Certificate File
        certificate_path = None
        if certificate and allowed_file(certificate.filename):
            filename = secure_filename(certificate.filename)
            certificate_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            certificate.save(certificate_path)

        # Insert into MongoDB
        educator_data = {
            "fullname": fullname,
            "email": email,
            "password": hashed_password,
            "gender": gender,
            "qualification": qualification,
            "certificate": certificate_path
        }
        mongo.db.educators.insert_one(educator_data)
        jsonify({"message": "Educator registered successfully!"}), 201
        return render_template('educator_login.html')
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

'''@app.route('/student_login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = mongo.db.students.find_one({"username": username})

        if user and check_password_hash(user["password"], password):
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))  # Redirect to student dashboard
        else:
            flash("Invalid username or password!", "danger")

    return render_template('student_login.html')

@app.route('/dashboard')
def dashboard():
    return "Welcome to the Student Dashboard"'''

@app.route("/student_forgot_password", methods=["POST"])
def student_forgot_password():
    email = request.form["email"]
    student = mongo.db.students.find_one({"email": email})

    if student:
        msg = Message("Your Login Credentials", sender=os.getenv("MAIL_USERNAME"), recipients=[email])
        msg.body = f"Username: {student['username']}\nPassword: {student['password']}"
        mail.send(msg)
        flash("Your credentials have been sent to your email.", "info")
    else:
        flash("Email not found.", "danger")

    return redirect(url_for("student_login"))

@app.route("/select_stream")
def select_stream():
    if "student" not in session:
        return redirect(url_for("student_login"))
    return render_template("select_stream.html")

# ------------------ EDUCATOR AUTH ------------------

@app.route("/educator_login", methods=["GET", "POST"])
def educator_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        educator = mongo.db.educators.find_one({"username": username})

        if educator and bcrypt.check_password_hash(educator["password"], password):
            session["educator"] = username
            return render_template("upload_materials_page.html")
        else:
            flash("Invalid username or password", "danger")
            return redirect(url_for("educator_login"))

    return render_template("educator_login.html")


@app.route("/educator_forgot_password", methods=["POST"])
def educator_forgot_password():
    email = request.form["email"]
    educator = mongo.db.educators.find_one({"email": email})

    if educator:
        msg = Message("Your Login Credentials", sender=os.getenv("MAIL_USERNAME"), recipients=[email])
        msg.body = f"Username: {educator['username']}\nPassword: {educator['password']}"
        mail.send(msg)
        flash("Your credentials have been sent to your email.", "info")
    else:
        flash("Email not found.", "danger")

    return redirect(url_for("educator_login"))

@app.route("/upload_materials", methods=["GET", "POST"])
def upload_materials():
    if "educator" not in session:
        return redirect(url_for("educator_login"))

    if request.method == "POST":
        material_type = request.form["material_type"]
        material_link = request.form["material_link"]

        mongo.db.study_materials.insert_one({
            "educator": session["educator"],
            "type": material_type,
            "link": material_link
        })  # ✅ Fixed

        flash("Study material uploaded successfully!", "success")

    return render_template("upload_materials.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))

# Run Flask App
if __name__ == "__main__":
    app.run(debug=True)