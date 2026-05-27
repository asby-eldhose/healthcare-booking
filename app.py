# app.py — Healthcare Booking System (Complete)
from flask import Flask, render_template, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DB_URL', 'sqlite:///local.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
limiter = Limiter(get_remote_address, app=app, default_limits=['200 per day'])

# ── MODELS ──────────────────────────────────────────────
class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email    = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role     = db.Column(db.String(10), default='user')

class Doctor(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(100), nullable=False)
    specialty = db.Column(db.String(100))
    available = db.Column(db.Boolean, default=True)

class Appointment(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    user_id   = db.Column(db.Integer, db.ForeignKey('user.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'))
    date      = db.Column(db.String(50))
    reason    = db.Column(db.String(300))
    status    = db.Column(db.String(20), default='pending')

# ── DECORATORS ──────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            return 'Access Denied', 403
        return f(*args, **kwargs)
    return decorated

# ── ROUTES ──────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=request.form['username'],
                    email=request.form['email'],
                    password=hashed)
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('5 per minute')
def login():
    error = None
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            return redirect('/dashboard')
        error = 'Invalid email or password'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
@login_required
def dashboard():
    appointments = Appointment.query.filter_by(user_id=session['user_id']).all()
    doctors = Doctor.query.filter_by(available=True).all()
    return render_template('dashboard.html', appointments=appointments, doctors=doctors)

@app.route('/book', methods=['POST'])
@login_required
def book():
    appt = Appointment(user_id=session['user_id'],
                       doctor_id=request.form['doctor_id'],
                       date=request.form['date'],
                       reason=request.form['reason'])
    db.session.add(appt)
    db.session.commit()
    return redirect('/dashboard')

@app.route('/cancel/<int:id>')
@login_required
def cancel(id):
    appt = Appointment.query.get_or_404(id)
    if appt.user_id != session['user_id']:
        return 'Forbidden', 403
    db.session.delete(appt)
    db.session.commit()
    return redirect('/dashboard')

# ── ADMIN ROUTES ────────────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin():
    users = User.query.all()
    appointments = Appointment.query.all()
    doctors = Doctor.query.all()
    return render_template('admin.html', users=users, appointments=appointments, doctors=doctors)

@app.route('/admin/approve/<int:id>')
@login_required
@admin_required
def approve(id):
    appt = Appointment.query.get_or_404(id)
    appt.status = 'approved'
    db.session.commit()
    return redirect('/admin')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)