
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import InputRequired, Length, EqualTo, Email
from flask_mail import Mail, Message
import os
import secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), nullable=False, default='user')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def create_users():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin_user = User(username='admin', email='admin@example.com', password=hashed_password, role='admin', is_verified=True)
        db.session.add(admin_user)
    if not User.query.filter_by(username='testuser').first():
        hashed_password = bcrypt.generate_password_hash('user123').decode('utf-8')
        user = User(username='testuser', email='user@example.com', password=hashed_password, role='user', is_verified=True)
        db.session.add(user)
    db.session.commit()

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[InputRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20)])
    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password, role=form.role.data)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)
        flash('Registration successful! Please check your email to verify your account.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html', form=form)

def send_verification_email(user):
    token = secrets.token_urlsafe(32)
    verification_link = url_for('verify_email', token=token, _external=True)
    msg = Message('Verify Your Email', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'Click the link to verify your email: {verification_link}'
    mail.send(msg)

@app.route('/verify_email/<token>')
def verify_email(token):
    flash('Email verified successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))
    users = User.query.all()
    return render_template('admin.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)
