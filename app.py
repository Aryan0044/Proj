from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class PDFFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@app.route("/home")
def home():
    return render_template('index.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if 'login' in request.form:
            # Handle login
            username_or_email = request.form.get('username_or_email')
            password = request.form.get('password')
            user = User.query.filter((User.username==username_or_email) | (User.email==username_or_email)).first()
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Login Unsuccessful. Please check username and password', 'danger')
        elif 'signup' in request.form:
            # Handle signup
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created!', 'success')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/upload", methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        files = request.files.getlist('pdf_files')

        for file in files:
            if file and file.filename.endswith('.pdf'):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                pdf_file = PDFFile(title=title, description=description, filename=filename, user_id=current_user.id)
                db.session.add(pdf_file)
                db.session.commit()

        flash('File(s) uploaded successfully!', 'success')
        # return redirect(url_for('home'))
    return render_template('upload.html')

@app.route("/user_pdfs")
@login_required  # Ensure the user is logged in to access this route
def user_pdfs():
    user_pdfs = PDFFile.query.filter_by(user_id=current_user.id).all()
    return render_template('user_pdfs.html', pdfs=user_pdfs)

@app.route("/all_pdfs")
def all_pdfs():
    all_pdfs = PDFFile.query.all()
    return render_template('all_pdfs.html', pdfs=all_pdfs)

@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route("/about")
def about():
    return render_template('about.html')

@app.route("/post1")
def post1():
    return render_template('post1.html')

@app.route("/post2")
def post2():
    return render_template('post2.html')

@app.route("/post3")
def post3():
    return render_template('post3.html')

@app.route("/post4")
def post4():
    return render_template('post4.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
