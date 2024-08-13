# curl -u name:pwd -i -X GET http://127.0.0.1:5000/profile


from flask import Flask, request, render_template, redirect, g,jsonify
from flask_sqlalchemy import SQLAlchemy

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

from werkzeug.security import generate_password_hash, check_password_hash
#from flask_login import UserMixin, LoginManager, login_user, login_required, current_user
import uuid
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()
db = SQLAlchemy()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'

db.init_app(app)

class User(#UserMixin,
	db.Model):
	userid = db.Column(db.String(100), primary_key=True) # primary keys are required by SQLAlchemy
	name = db.Column(db.String(1000), unique=True)
	password = db.Column(db.String(100))
	text = db.Column(db.String(1000))
	def get_id(e):
		return e.userid


@app.route('/profile')
@auth.login_required
def get_resource():
    return jsonify({ 'name': g.user.name })


@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(name = username).first()
    if not user or not check_password_hash(user.password, password):
        return False
    g.user = user
    return True

@app.route('/signup', methods=['POST'])
def signup_post():
	# code to validate and add user to database goes here
	name = request.form.get("name")
	password = request.form.get("password")

	if not name:
		return "wheres your name"
	if not password:
		return "wheres your password"
	if User.query.filter_by(name=name).first(): # if a user is found, we want to redirect back to signup page so user can try again
		return "bad name"

	# create a new user with the form data. Hash the password so the plaintext version isn't saved.
	new_user = User( userid=str(uuid.uuid4().fields[-1]),name=name, password=generate_password_hash(password, method='pbkdf2:sha256'),text="")

	# add the new user to the database
	db.session.add(new_user)
	db.session.commit()
	
	return "success"


with app.app_context():
	db.create_all()
if __name__ == '__main__':
	app.run(host='0.0.0.0', port=8080)