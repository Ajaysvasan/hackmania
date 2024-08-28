from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///fitness_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    avatar = db.Column(db.String(200))

def check_json_fields(data, required_fields):
    missing = [field for field in required_fields if field not in data]
    if missing:
        return jsonify({"message": f"Missing {', '.join(missing)}"}), 400
    return None    

# Routes
@app.route('/')
def index():
    return render_template('register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

    
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()

        print("ready",data)
        missing_fields = check_json_fields(data, ["username", "email", "password"])
        if missing_fields:
            return missing_fields


        # if not username or not email or not password:
        #     return jsonify({"message": "Missing required fields"}), 400
        username = data['username']
        email = data['email']
        password =  data['password']
        # try:
        #     username = request.form.get('username')
        #     email = request.form.get('email')
        #     password = request.form.get('password')
        #     print(username,email,password)
        #     hashed_password = generate_password_hash(data['password'])
        #     new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
        #     db.session.add(new_user)
        #     db.session.commit()
        # except IntegrityError:
        #     db.session.rollback()
        #     return jsonify({"message": "Username or email already exists"}), 400
        # except Exception as e:
        #     db.session.rollback()
        #     return jsonify({"message": f"An error occurred: {str(e)}"}), 500


        try:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, email=email, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            return jsonify({"message": "Username or email already exists"}), 400

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            access_token = create_access_token(identity=user.id)
            return redirect(url_for('dashboard'))
        else:
            return jsonify({"message": "Invalid credentials"}), 401

    return render_template('login.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return render_template('register.html', user=user)  # Using register.html as it contains the dashboard section

@app.route('/logout')
def logout():
    # For simplicity, we'll just redirect to the login page
    # In a real application, you'd want to invalidate the JWT token
    return redirect(url_for('login'))

@app.route('/create_avatar', methods=['POST'])
@jwt_required()
def create_avatar():
    current_user_id = get_jwt_identity()
    avatar_url = request.form.get('avatar_url')
    
    user = User.query.get(current_user_id)
    user.avatar = avatar_url
    db.session.commit()
    
    return jsonify({"message": "Avatar created successfully"}), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
