import os
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash ,session
from werkzeug.utils import secure_filename
from secrets import token_hex
from dataProcessing import *
from Threads import *
from flask import send_file,make_response
import time
from werkzeug.security import generate_password_hash ,check_password_hash
from bson.objectid import ObjectId
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_wtf.csrf import CSRFProtect
from pymongo import MongoClient
from flask_wtf import csrf

from flask import session, request, abort
from secrets import token_hex
#VALIDATION OF FORM 
class RegistrationForm(FlaskForm):
    class Meta:
        csrf = True

    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
      
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
# Flask app    
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(64) #secret key for WTF forms
csrf = CSRFProtect(app)

script = ''

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['maindb']
users_collection = db['users']

UPLOAD_FOLDER = '.'
ALLOWED_EXTENSIONS = set(['py'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config["CACHE_TYPE"] = "null"

#main functions 

def is_valid_credentials(username, password):
    user = users_collection.find_one({'username': username, 'password': password})
    return user is not None

def resultE():
    path = "./Segments"
    dir_list = os.listdir(path)
    print(dir_list)
    return render_template('Result.html',dir_list = dir_list)

def resultD():
    return render_template('resultD.html')

def start():
  content = open('./Original.txt','r')
  content.seek(0)
  first_char = content.read(1) 
  if not first_char:
    return render_template('Empty.html')
  else:
    return render_template('Option.html')
  
def is_valid_credentials(username, password):
    user = users_collection.find_one({'username': username})
    if user is None:
        return False
    return check_password_hash(user['password'], password)
  
@app.route('/encrypt/')
def EncryptInput():
  Segment()
  gatherInfo()
  HybridCrypt()
  return resultE()

@app.route('/decrypt/')
def DecryptMessage():
  st=time.time()
  HybridDeCrypt()
  et=time.time()
  print(et-st)
  trim()
  st=time.time()
  Merge()
  et=time.time()
  print(et-st)
  return resultD()

@app.route('/')
def index():
  return render_template('Main.html')

@app.route('/Empty')
def Empty():
  return render_template('Empty.html')

@app.route('/home')
def home():
  return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    username = form.username.data
    password = form.password.data
    if is_valid_credentials(username, password):
      #session['username'] = username
      return redirect(url_for('Empty'))
    else:
      flash('Invalid username or password', 'danger')
  else:
    # If form is not valid, print the form errors
    print(form.errors)
  return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Hash the password
        hashed_password = generate_password_hash(password)
        # Check if the user already exists
        existing_user = users_collection.find_one({'username': username})
        if existing_user is None:
            users_collection.insert_one({'username': username, 'password': hashed_password})
            return redirect(url_for('login'))
        else:
            return render_template('register.html', form=form, error='Username already exists')
    else:
        # If form is not valid, print the form errors
        print(form.errors)
    return render_template('register.html', form=form)
  
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        username = session['username']
        return render_template('Empty.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))
  
@app.route('/about')
def about():
  return render_template('about.html')

@app.route('/en')
def en():
  return render_template('index.html')

def allowed_file(filename):
  return '.' in filename and \
    filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/return-files-key/')
def return_files_key():
  try:
    return send_file('./Original.txt',attachment_filename='Original.txt',as_attachment=True)
  except Exception as e:
    return str(e)
  
  
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

@app.route('/return-files-data/')
def return_files_data():
    try:
        response = make_response(send_file('./Output.txt', as_attachment=True))
        response.headers["Content-Disposition"] = "attachment; filename=Output.txt"
        return response
    except Exception as e:
        return str(e)
      
      


@app.route('/data/', methods=['POST'])
@csrf.exempt
def upload_file():
  if 'file' not in request.files:
    return render_template('Nofile.html')
  file = request.files['file']
  if file.filename == '':
    return render_template('Nofile.html')
  if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'Original.txt'))
    return start()

  return render_template('Invalid.html')

    
if __name__ == '__main__':
  app.run(debug=True)
#debuging false last step 
