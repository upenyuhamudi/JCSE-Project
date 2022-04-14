from email.mime import application
import sqlite3
from telnetlib import STATUS
import bcrypt
from flask import Flask, redirect, render_template, request,url_for,flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
import logging



app = Flask(__name__)

@app.route("/static/<path:path>")
def static_dir(path):
    return send_from_directory("static", path)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'secretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

connection = sqlite3.connect('database.db', check_same_thread=False)
cursor = connection.cursor()

#Create Application Table
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
    discipline = db.Column(db.String(50), nullable=False)
    gpa = db.Column(db.String(10), nullable=False)
    application_status = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)


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

    #email = StringField(validators=[InputRequired(), Length(min=10, max=80)], render_kw={"placeholder": "email"})

    discipline = StringField(validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "discipline"})

    gpa = StringField(validators=[InputRequired(), Length(min=1, max=10)], render_kw={"placeholder": "gpa"})

    submit = SubmitField("Submit")  

class UpdateApplication(FlaskForm):
   
    application_status_update = StringField(validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "status"})
    
    submit = SubmitField("Update Application Status")

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
                print(user.id)
                if user.usertype == 'applicant':
                    return redirect(url_for('dashboard',user_id=user.id))
                return redirect(url_for('admin_dashboard',user_id=user.id))
    return render_template('login.html',form=form)

@app.route('/dashboard', methods = ['GET','POST'])
def dashboard():
    user_id = request.args.get('user_id')
    return render_template('dashboard.html',user = user_id)

@app.route('/admin_dashboard', methods = ['GET','POST'])
def admin_dashboard():
    user_id = request.args.get('user_id')
    applications = Forms.query.all()
    return render_template('admin_dashboard.html',user = user_id, data=applications)


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
    user_id = request.args.get('user_id')
    return render_template('form.html',user = user_id)

@app.route('/view_my_application',methods = ['GET','POST'])
def view_my_application():

   user_id = request.args.get('user_id')
   user1 = str(user_id)

   cursor = connection.execute('SELECT firstname, lastname, address, discipline, gpa, application_status FROM forms WHERE user_id =' +user1)
   return render_template('view_application.html', items=cursor.fetchall(),user = user_id)
   #return render_template('view_application.html')

@app.route('/view_my_application_status')
def view_my_application_status():
   return render_template('view_application_status.html')

@app.route('/addtoformtable', methods=['GET', 'POST'])
def addtoformtable():
    form = ApplicationForm()
    user = request.args.get('user_id')
    new_form = Forms(firstname=form.firstname.data, lastname=form.lastname.data, address=form.address.data, discipline=form.discipline.data, gpa=form.gpa.data, application_status='Pending',user_id = user)
    db.session.add(new_form)
    db.session.commit()
    return render_template('result.html')

    #if form.validate_on_submit():
        #new_form = Forms(firstname=form.firstname.data, lastname=form.lastname.data, address=form.address.data, email=form.email.data, discipline=form.discipline.data, gpa=form.gpa.data)
        #db.session.add(new_form)
        #db.session.commit()
        #return redirect(url_for('login'))

    #return render_template('duplicate_application.html', form=form)

@app.route('/update_application/<form_id>/', methods=('GET', 'POST'))
def update_application(form_id):
    applicant = Forms.query.get(form_id)    
    return render_template('update_application.html',applicant=applicant)



@app.route('/application_updated/<form_id>/<application_status>', methods=('GET', 'POST'))
def application_updated(form_id,application_status):  
    if request.method == 'POST':
        application = Forms.query.get(form_id)
        application.application_status = application_status
        db.session.commit()
        db.session.close_all()
        return redirect(url_for('admin_dashboard'))    

logging.basicConfig(level=logging.DEBUG)
logging.debug('This will get logged') 

logging.basicConfig(level=logging.INFO)
logging.info('This is an info message')
logging.warning('This is a warning message')
logging.error('This is an error message')
logging.critical('This is a critical message') 

if __name__ == '__main__':
    app.run(debug=True)





