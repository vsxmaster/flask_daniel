from flask import Flask, redirect, render_template, request, url_for, session,flash,abort
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_security import UserMixin
from flask_bcrypt import Bcrypt, generate_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, current_user, login_required, login_user, LoginManager, logout_user, login_manager,AnonymousUserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy.sql import func
from wtforms import BooleanField, IntegerField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import (DataRequired, InputRequired, Length)
from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os, sqlite3,smtplib, re
import yaml

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
bcrypt = Bcrypt(app)


conf = yaml.safe_load(open('conf/application.yml'))
email = conf['user']['email']
pwd = conf['user']['password']

server = smtplib.SMTP('smtp.gmail.com', 587)
server.ehlo()
server.starttls()
server.login(email, pwd)
s = URLSafeTimedSerializer('1EMuskYdgB3BtwxpEP46txN5EAN8KnA7dEAWE')

db = SQLAlchemy(app)
conn = sqlite3.connect ('database.db')

uri = os.getenv("DATABASE_URL")

if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
    
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://koxfcfgztqnqxg:aeea485f0d117151af96ddebe96d64401c2a4dd0e279a2862491378250eeba82@ec2-18-215-41-121.compute-1.amazonaws.com:5432/d60qea7qhsgaco'
app.config['SECRET_KEY'] = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=3)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.anonymous_user=AnonymousUserMixin
login_manager.login_message_category = "info"
login_manager.login_view = "memberpage"
login_manager.login_message = "Access denied! You\'ll have to Log in first!"
login_manager.session_protection = "strong"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    studentID = db.Column(db.String(20, collation='NOCASE'), nullable=False, unique=True)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(80, collation='NOCASE'), nullable=False, unique=True)
    age = db.Column(db.Integer)
    phonenumber = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True),server_default=func.now())
    password= db.Column(db.String(256), nullable=False)
    bio = db.Column(db.Text)
    acc_verify = db.Column(db.Boolean, default=False, nullable=False, server_default='1')
    is_commitee = db.Column(db.Boolean, default=False)
    is_admin=db.Column(db.Boolean, default=False)
    attendees = db.relationship('Attendance', backref='members_attended')
    
    def __init__(self,studentID,firstname,lastname,email,age,phonenumber, password, bio, acc_verify,is_admin,is_commitee):
        self.studentID = studentID
        self.firstname = firstname
        self.lastname = lastname
        self.email = email
        self.age=age
        self.phonenumber=phonenumber
        self.password = generate_password_hash(password)
        self.bio = bio
        self.acc_verify = bool(acc_verify)
        self.is_commitee = bool(is_commitee)
        self.is_admin=bool(is_admin)
    
    
    def verify_password(self, pwd):
        return check_password_hash(self.password, pwd)    
    
    
    def __repr__(self):
        return f'''
    StudentID:{self.studentID}  ||||| Email:{self.email} ||||| Phonenumber:{self.phonenumber} ||||||
    '''
    
class Events(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150, collation='NOCASE'), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(250, collation='NOCASE'), nullable=False)
    location = db.Column(db.String, nullable=False)
    status = db.Column(db.String, nullable=False)
    passcode = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True),server_default=func.now())
    event_joined = db.relationship('Attendance', backref='event_joined')
    
    
    def __init__(self,title,date,time,description,location,status,passcode):
        self.title = title
        self.date = date
        self.time = time
        self.description = description
        self.location= location
        self.status= status
        self.passcode= passcode

    def __repr__(self):
        return f'''
    Title:{self.title} ||||| Date:{self.date} ||||| Time:{self.time} ||||| Location:{self.location} ||||||
    '''
        
class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time_of_marking_attendance = db.Column(db.DateTime(timezone=True),server_default=func.now())
    attendees_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    enroll_id = db.Column(db.Integer, db.ForeignKey('events.id'))

    def __repr__(self):
        return f'<Student_Events {self.id}>'
    
    
class RegisterForm(FlaskForm):
    studentID = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "studentID"})
    firstname = StringField(validators=[InputRequired(), Length(min=3, max=20)], render_kw={"placeholder": "Your first name"})
    lastname  = StringField(validators=[InputRequired(), Length(min=3, max=20)], render_kw={"placeholder": "Your last name"})
    email = StringField(validators=[InputRequired(), DataRequired()], render_kw={"placeholder":"Email address"})
    age =  IntegerField(validators=[InputRequired()], render_kw={"placeholder": "Your age"})
    phonenumber = StringField(validators=[InputRequired()], render_kw={"placeholder": "Your phonenumber"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    bio = TextAreaField(validators=[InputRequired()], render_kw={"placeholder": "Describe yourself"})
    acc_verify = BooleanField(validators=[InputRequired()])
    submit = SubmitField("Register")
    submit23 = SubmitField("Save")
    submit_reset = SubmitField("Change password")

class LoginForm(FlaskForm):
    studentID = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder"  :"studentID"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={" placeholder" :"Password"})
    remember = BooleanField('Remember Me')
    submit = SubmitField("Login")
    
class ResetRequestForm(FlaskForm):
    email = StringField(validators=[InputRequired(), DataRequired()], render_kw={"placeholder":"Email address"})
    antiphising = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder":"Your anti-phising code"})
    submit = SubmitField(label="Reset Password", validators=[DataRequired()])

class CommiteeAddEventForm(FlaskForm):
    title = StringField(validators=[InputRequired(), Length(min=3, max=80)], render_kw={"placeholder"  :"Event title"})
    date = StringField(validators=[InputRequired(), Length(min=3, max=80)], render_kw={"placeholder"  :"Event date"})
    time = StringField(validators=[InputRequired(), Length(min=3, max=80)], render_kw={"placeholder"  :"Event time"})
    description = TextAreaField(validators=[InputRequired()], render_kw={"placeholder": "Event Description"})
    location = StringField(validators=[InputRequired(), Length(min=3, max=80)], render_kw={"placeholder"  :"Event location"})
    status = StringField(validators=[InputRequired(), Length(min=3, max=80)], render_kw={"placeholder" :"Event status"})
    passcode = StringField(validators=[Length(min=3, max=80)], render_kw={"placeholder" : "Passcode"})
    submit = SubmitField(label="Add Event", validators=[DataRequired()])
    submit2 = SubmitField(label="Save Edit", validators=[DataRequired()])
    submit3 = SubmitField(label="Record Attendence", validators=[DataRequired()])

app.config['FLASK_ADMIN_SWATCH'] = 'Flatly'
admin = Admin(app, name='UNITEN RUNNING CLUB ADMINISTRATOR', template_mode='bootstrap3')

class ModelView(ModelView):
    def is_accessible(self):
        if current_user.is_anonymous == True:
            return abort(404)
        if current_user.is_admin:
            return True
        if current_user.is_commitee:
            return True
        else:
            return abort(404)
    
    def inaccessible_callback(self, name, **kwargs):
        return False
    
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Events, db.session))
admin.add_view(ModelView(Attendance, db.session))

@app.route("/adminspace")
@login_required
def adminspace():
    if current_user.is_anonymous == True:
        return abort(404)
    if current_user.is_admin:
        return redirect('/admin/')
    if current_user.is_commitee:
        return redirect('/admin/')
    else:
        return abort(404)
            

@app.route("/")
def homelayout():
    return render_template('home.html')

@app.route("/insert",methods=['GET','POST'])
def insert():
    form = CommiteeAddEventForm()
    form=form
    if request.method == 'POST':
        title = request.form.get('title')
        date = request.form.get('date')
        time = request.form.get('time')
        description = request.form.get('description')
        location = request.form.get('location')
        status = request.form.get('status')
        passcode = request.form.get('passcode')
    
        my_data = Events(title=title, 
                    date=date, 
                    time=time, 
                    description=description, 
                    location=location,
                    passcode=passcode,
                    status=status)
        db.session.add(my_data)
        db.session.commit()
        flash("Succesfuly created Event!")
        return redirect(url_for('commdashboard'))


@app.route("/update/<id>/",methods=['GET','POST'])
def update(id):
    form=CommiteeAddEventForm()
    post = Events.query.get_or_404(id)
    
    if request.method == 'POST':
        post.title = form.title.data
        post.date = form.date.data
        post.time = form.time.data
        post.description = form.description.data
        post.location = form.location.data
        post.status = form.status.data
        post.passcode = form.passcode.data     
        db.session.add(post)
        db.session.commit()
        flash("Event successfuly edited!")
        return redirect(url_for('commdashboard'))

    return render_template('commitee_dashboard.html',form=form,post=post,id=post.id)

@app.route("/update_member/<id>",methods=['GET','POST'])
@login_required
def memberupdate(id):
    form=RegisterForm()
    updates = User.query.get_or_404(id)
    if request.method == 'POST':
        updates.firstname = form.firstname.data
        updates.lastname = form.lastname.data
        updates.email = form.email.data
        updates.age = form.age.data
        updates.phonenumber = form.phonenumber.data
        updates.bio = form.bio.data    
        db.session.add(updates)
        db.session.commit()
        flash("Member details successfuly edited!")
        return redirect(url_for('dashboard'))
    
    form.firstname.data = updates.firstname
    form.lastname.data = updates.lastname
    form.email.data = updates.email
    form.age.data = updates.age
    form.phonenumber.data = updates.phonenumber
    form.bio.data = updates.bio
    
    return render_template('update_biodata.html',form=form,updates=updates,id=updates.id)


@app.route("/delete/<id>/",methods=['GET','POST'])
def delete(id):
    my_data = Events.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("Event deleted successfully")
    return redirect(url_for('commdashboard'))

@app.route("/memberdelete/<id>/",methods=['GET','POST'])
@login_required
def memberdelete(id):
    mystudent = User.query.get(id)
    db.session.delete(mystudent)
    db.session.commit()
    flash("Member deleted successfully. You are no longer a Uniten Running Club Member. Goodbye!")
    return redirect(url_for('homelayout'))

@app.route("/member_loginpage/", methods=['GET','POST'])
def memberpage():
    form = LoginForm()
    studentID = form.studentID.data
    password = form.password.data

    if form.validate_on_submit(): 
        user = User.query.filter_by(studentID=studentID).first()
        
        if not user:
            return render_template('404.html')
    
        login_user(user, remember=True)
        
        if user and user.verify_password(password):
            login_user(user, remember=True)
            session['logged_in']=True
            return redirect(url_for('dashboard'))
        else:
            flash("Please check your login details correctly and try again",'danger')

    return render_template('member_loginpage.html', form=form)


@app.route("/logindashboard/")
@login_required
def dashboard():
    form=CommiteeAddEventForm()
    posts = Events.query.order_by(Events.created_at.desc())

    if current_user.is_active:
        return render_template('testinglogin.html',posts=posts,form=form, id=Events.id)
    

@app.route("/mark_attendance",methods=['GET','POST'])
def mark_attendance():
    form=CommiteeAddEventForm()
    record_member = User.query.filter_by(id=current_user.id).first()
    record_event = Events.query.order_by(Events.created_at.desc()).first()
    passcode=Events.query.filter_by(passcode=form.passcode.data).first()
    
    if request.method == 'POST':
    
        if not passcode:
            flash("Invalid Passcode entered!")
            return redirect(url_for('dashboard'))
        
        boy = Attendance(members_attended=record_member,event_joined=record_event)
        db.session.add(boy)
        db.session.commit()
        flash("Attendance sucessfully recorded!")

    return redirect(url_for('dashboard',form=form))


@app.route("/commitee-dashboard/")
@login_required
def commdashboard():
    form=CommiteeAddEventForm()
    posts = Events.query.order_by(Events.created_at.desc())
    
    if current_user.is_commitee:
        return render_template('commitee_dashboard.html',posts=posts,form=form, id=Events.id)
    else:
        flash('Unauthorised access detected!')
        return redirect(url_for('dashboard'))
    

@app.route("/member_signup_home/")
def membersignup_page():
    return render_template('member_signup_home.html')

@app.route("/member_registeration/",methods=('GET','POST'))
def memberregistration_page(): 
    form = RegisterForm()
    
    if request.method == 'POST':
        studentID = request.form.get('studentID')
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        age = request.form.get('age')
        phonenumber = request.form.get('phonenumber')
        password = request.form.get('password')
        bio = request.form.get('bio')
        acc_verify = request.form.get('acc_verify')
        is_admin = request.form.get('is_admin')
        is_commitee = request.form.get('is_commitee')
        
        new_student = User(studentID=studentID,
                        firstname=firstname,
                        lastname=lastname,
                        email=email,
                        age=age,
                        phonenumber=phonenumber,
                        password=password,
                        bio=bio,
                        acc_verify=acc_verify,
                        is_commitee=is_commitee,
                        is_admin=is_admin)
        
        if User.query.filter_by(studentID=studentID).first():
            flash("Registration Unsuccessful! Student ID already exist!")
            return redirect(url_for('memberregistration_page'))
        
        if User.query.filter_by(email=email).first():
            flash("Registration Unsuccessful! Email address already exist!")
            return redirect(url_for('memberregistration_page'))
        
        db.session.add(new_student)
        db.session.commit()
        flash("Member Registration is successful. Proceed to login.")
        return redirect(url_for('homelayout'))
    
    return render_template('/member_registration.html', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.pop('logged_in', None)
    flash("You have been logged out! Thank you for using me and have a nice day", "info")
    return redirect(url_for('homelayout'))

@app.route('/admin/logout')
def adminlogout():
    logout_user()
    flash("You have been logged out!", "info")
    return redirect(url_for('homelayout'))


@app.route("/rest_request/", methods=['GET','POST'])
def reset_request():
    form = ResetRequestForm()
    code = form.antiphising.data
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='email-confirm')
            msg=f'''User has requested to reset password. Please click on the link below to reset
{url_for('userChangePassword',token=token,_external=True) } 

anti-phising-code : {code}''' 
            server.sendmail('unitenrunningclub.superuser@gmail.com', user.email, msg)
            flash('Reset request email successfully sent. Please check your email', 'success')
            return redirect(url_for('memberpage'))
    
    return render_template('Reset_request.html', title='Rest Request', form=form)



@app.route('/changepassword/<token>',methods=["POST","GET"])
def userChangePassword(token):
    form = RegisterForm()
    if request.method == 'POST':
        email=request.form.get('email')
        password=request.form.get('password')
        try:
            email = s.loads(token, salt='email-confirm', max_age=60)
        except SignatureExpired:
            return '<h1> Oh-oh~ Your token has already expired!</h1>'
        
        if email == "" or password == "":
            flash('Please fill the field','danger')
            return render_template('change_password.html')
        else:
            users=User.query.filter_by(email=email).first()
            if users:
                password=generate_password_hash(password)
                User.query.filter_by(email=email).update(dict(password=password))
                db.session.commit()
                flash('Password Change Successfully','success')
                return redirect(url_for('homelayout'))
            else:
                flash('Invalid Email','danger')
                return render_template('change_password.html')
            
    return render_template('change_password.html',title="Change Password", form=form)

if __name__ == '__main__':
    app.run(debug=True)

