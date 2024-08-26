# curl -u name:pwd -i -X GET http://127.0.0.1:5000/profile


import uuid
from flask import Flask, request, render_template, redirect, g, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user
#from flask_httpauth import HTTPBasicAuth
#auth = HTTPBasicAuth()
db = SQLAlchemy()

"""
import mysql.connector

mydb = mysql.connector.connect(
  host="34.44.86.36",
  user="gleaming-terra-425802-r2:us-central1:my-sql-db",
  password='.$~v"\\DS%m/c1VI"'
)

print(mydb)
exit()
"""


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db.init_app(app)

class User(UserMixin, db.Model):
	userid = db.Column(db.String(100), primary_key=True) # primary keys are required by SQLAlchemy
	username = db.Column(db.String(1000), unique=True)
	password = db.Column(db.String(100))
	name = db.Column(db.String(1000), nullable=True)
	text = db.Column(db.String(100000), nullable=True)
	hobbies = db.Column(db.String(1000), nullable=True)
	birthday = db.Column(db.String(100), nullable=True)
	school = db.Column(db.String(100), nullable=True)
	def get_id(e):
		return e.userid


login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
	# since the user_id is just the primary key of our user table, use it in the query for the user
	return User.query.get(user_id)

@login_manager.request_loader
def load_user_from_request(request):
	if request.authorization:
		user = load_user(request.authorization.username)
		if user and check_password_hash(user.password, request.authorization.password):
			return user
	return None


@app.route('/')
def login():
	return render_template('login.html')


@app.route('/api/get_user_info')
@login_required
def get_resource():
    return jsonify({
			'user_id': current_user.userid,
			'username': current_user.username,
			'name': current_user.name,
			'text': current_user.text,
			'hobbies': current_user.hobbies,
			'birthday': current_user.birthday,
			'school': current_user.school
		})


def signup(request):
	# code to validate and add user to database goes here
	username = request.form.get("username")
	password = request.form.get("password")
	verify_password = request.form.get("verify_password")

	if not username:
		return ("wheres your username", None)
	if not password:
		return ("wheres your password", None)
	if password != verify_password:
		return ("wrong password", None)
	if User.query.filter_by(username=username).first(): # if a user is found, we want to redirect back to signup page so user can try again
		return ("bad username", None)

	# create a new user with the form data. Hash the password so the plaintext version isn't saved.
	new_user = User( userid=str(uuid.uuid4().fields[-1]), username=username, password=generate_password_hash(password, method='pbkdf2:sha256'))

	# add the new user to the database
	db.session.add(new_user)
	db.session.commit()
	
	return ("success", new_user)


@app.route('/api/signup', methods=['POST'])
def api_signup_post():
	(message, new_user) = signup(request)

	if not new_user:
		return jsonify({'success':False,'error':message})

	return jsonify({'success':True,'user_id':new_user.userid})

@app.route('/signup', methods=['POST'])
def signup_post():
	(message, new_user) = signup(request)

	if not new_user:
		return message

	login_user(new_user, remember=True)
	return redirect("/profile")

def do_login(request):
	username = request.form.get("username")
	password = request.form.get("password")

	user = User.query.filter_by(username=username).first()

	# check if the user actually exists
	# take the user-supplied password, hash it, and compare it to the hashed password in the database
	if not user or not password or not check_password_hash(user.password, password):
		return ("not user or not password",None)
	
	return ("success",user)

@app.route('/login', methods=['POST'])
def login_post():
	(message, user) = do_login(request)

	if not user:
		return message

	# if the above check passes, then we know the user has the right credentials
	login_user(user, remember=True)
	return redirect("/profile")

@app.route('/api/login', methods=['POST'])
def api_login_post():
	(message, user) = do_login(request)

	if not user:
		return jsonify({'success':False,'error':message})

	return jsonify({'success':True,'user_id':user.userid})

@app.route('/api/save_user_info', methods=['POST'])
@login_required
def save_user_info():
	current_user.text = request.form.get("text")
	current_user.hobbies = request.form.get("hobbies")
	current_user.birthday = request.form.get("birthday")
	current_user.school = request.form.get("school")
	current_user.name = request.form.get("name")
	db.session.commit()
	return jsonify({'success':True})

@app.route('/api/send_text')
@login_required
def send_text():
	question = request.form.get("question")
	return jsonify({ 'success':True, 'answers':['e','eeeeeee','hhjxcvfnxvk'] })
	#TODO: call chatgpt api

with app.app_context():
	db.create_all()
if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8080)