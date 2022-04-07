import bcrypt
from flask import Flask, redirect, render_template,url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    emailaddress = db.Column(db.String(80), nullable=False, unique = True)
    password = db.Column(db.String(80), nullable=False)
    usertype = db.Column(db.String(20), nullable=True)

class LoginForm(FlaskForm):
    emailaddress = StringField(validators=[InputRequired(),Length(min=4,max=20),Email()],render_kw={"placeholder": "Email Address"})

    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

class RegisterForm(FlaskForm):
    emailaddress = StringField(validators=[InputRequired(),Length(min=4,max=80),Email()], render_kw={"placeholder": "Email Address"})

    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_email(self, emailaddress):
        existing_email = User.query.filter_by(emailaddress=emailaddress.data).first()
        
        if existing_email:
            raise ValidationError("The email address already has an account. Please choose a different email address")

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods = ['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(emailaddress=form.emailaddress.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

@app.route('/dashboard', methods = ['GET','POST'])
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods = ['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(emailaddress=form.emailaddress.data,password=hashed_password,usertype='applicant')
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
