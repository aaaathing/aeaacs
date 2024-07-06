from flask import Flask, request, render_template, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user
import uuid
db = SQLAlchemy()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db.init_app(app)

class User(UserMixin,db.Model):
	userid = db.Column(db.String(100), primary_key=True) # primary keys are required by SQLAlchemy
	name = db.Column(db.String(1000), unique=True)
	password = db.Column(db.String(100))
	text = db.Column(db.String(1000))
	def get_id(e):
		return e.userid

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

@app.route('/login')
def login():
	return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
	return current_user.name

@login_manager.user_loader
def load_user(user_id):
	# since the user_id is just the primary key of our user table, use it in the query for the user
	return User.query.get(user_id)

@app.route('/signup', methods=['POST'])
def signup_post():
	# code to validate and add user to database goes here
	name = request.form.get("name")
	password =request.form.get("password")

	if User.query.filter_by(name=name).first(): # if a user is found, we want to redirect back to signup page so user can try again
		return "bad name"

	# create a new user with the form data. Hash the password so the plaintext version isn't saved.
	new_user = User( userid=str(uuid.uuid4().fields[-1]),name=name, password=generate_password_hash(password, method='pbkdf2:sha256'),text="")

	# add the new user to the database
	db.session.add(new_user)
	db.session.commit()

	login_user(new_user, remember=True)
	return redirect("/profile")

@app.route('/login', methods=['POST'])
def login_post():
	name = request.form.get("name")
	password =request.form.get("password")

	user = User.query.filter_by(name=name).first()

	# check if the user actually exists
	# take the user-supplied password, hash it, and compare it to the hashed password in the database
	if not user or not check_password_hash(user.password, password):
		return "not user or not password"

	# if the above check passes, then we know the user has the right credentials
	login_user(user, remember=True)
	return redirect("/profile")


with app.app_context():
	db.create_all()
if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8080)