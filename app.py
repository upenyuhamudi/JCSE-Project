import sqlite3
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

connection = sqlite3.connect('database.db')
cursor = connection.cursor()

command1 = """CREATE TABLE IF NOT EXISTS forms(form_id INTEGER PRIMARY KEY, firstname STRING, lastname STRING, address STRING, email STRING, discipline STRING, gpa STRING)"""

cursor.execute(command1)
#cursor.execute('DROP TABLE forms')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    emailaddress = db.Column(db.String(80), nullable=False, unique = True)
    password = db.Column(db.String(80), nullable=False)
    usertype = db.Column(db.String(20), nullable=True)
   
class Forms(db.Model, UserMixin):
    form_id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    discipline = db.Column(db.String(50), nullable=False)
    gpa = db.Column(db.String(10), nullable=False)


class LoginForm(FlaskForm):
    emailaddress = StringField(validators=[InputRequired(),Length(min=4,max=80),Email()],render_kw={"placeholder": "Email Address"})

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
       
class ApplicationForm(FlaskForm):
    firstname = StringField(validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "firstname"})

    lastname = StringField(validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "lastname"})

    address = StringField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "address"})

    email = StringField(validators=[InputRequired(), Length(min=10, max=80)], render_kw={"placeholder": "email"})

    discipline = StringField(validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "discipline"})

    gpa = StringField(validators=[InputRequired(), Length(min=1, max=10)], render_kw={"placeholder": "gpa"})

    submit = SubmitField("Submit")

    def validate_email(self, email):
        existing_user_email = Forms.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("That email already exists. You have already applied")  

@app.before_first_request
def create_tables():
    db.create_all()               
       
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

@app.route('/new_application')
def new_application():
   return render_template('form.html')

@app.route('/view_my_application')
def view_my_application():
   return render_template('view_application.html')

@app.route('/view_my_application_status')
def view_my_application_status():
   return render_template('view_application_status.html')

@app.route('/addtoformtable', methods=['GET', 'POST'])
def addtoformtable():
    form = ApplicationForm()
    new_form = Forms(firstname=form.firstname.data, lastname=form.lastname.data, address=form.address.data, email=form.email.data, discipline=form.discipline.data, gpa=form.gpa.data)
    db.session.add(new_form)
    db.session.commit()
    return render_template('result.html')

    #if form.validate_on_submit():
        #new_form = Forms(firstname=form.firstname.data, lastname=form.lastname.data, address=form.address.data, email=form.email.data, discipline=form.discipline.data, gpa=form.gpa.data)
        #db.session.add(new_form)
        #db.session.commit()
        #return redirect(url_for('login'))

    #return render_template('duplicate_application.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
