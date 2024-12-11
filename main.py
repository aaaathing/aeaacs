from os import environ
import uuid
from flask import Flask, request, render_template, redirect, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from openai import OpenAI

client = OpenAI()
db = SQLAlchemy()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = environ.get("DATABASE_URL") or 'sqlite:///db.sqlite'

db.init_app(app)

class User(UserMixin, db.Model):
    userid = db.Column(db.String(100), primary_key=True)  # primary keys are required by SQLAlchemy
    username = db.Column(db.String(1000), unique=True)
    password = db.Column(db.String(1000))
    name = db.Column(db.String(1000), nullable=True)
    text = db.Column(db.String(100000), nullable=True)
    hobbies = db.Column(db.String(1000), nullable=True)
    birthday = db.Column(db.String(100), nullable=True)
    school = db.Column(db.String(100), nullable=True)
    introduction = db.Column(db.String(100000), nullable=True)

    def get_id(self):
        return self.userid

class Answer(db.Model):
    answerid = db.Column(db.String(100), primary_key=True)
    userid = db.Column(db.String(100))
    question = db.Column(db.String(100000))
    chosen_answer = db.Column(db.String(100000))

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # Since the user_id is just the primary key of our user table, use it in the query for the user
    return User.query.get(user_id)

@login_manager.request_loader
def load_user_from_request(request):
    if request.authorization:
        username = request.authorization.username
        password = request.authorization.password
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            return user
    return None

@app.route('/')
def login():
    if current_user.is_authenticated:
        return render_template('use-it.html')
    else:
        return render_template('home.html')

@app.route('/edit')
@login_required
def edit_info():
    return render_template('edit.html')

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
        'school': current_user.school,
        'introduction': current_user.introduction
    })

def signup(request):
    # Code to validate and add user to database goes here
    username = request.form.get("username")
    password = request.form.get("password")
    verify_password = request.form.get("verify_password")

    if not username:
        return ("Where's your username?", None)
    if not password:
        return ("Where's your password?", None)
    if password != verify_password:
        return ("Passwords do not match.", None)
    if User.query.filter_by(username=username).first():
        return ("Username already exists.", None)

    # Create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(userid=str(uuid.uuid4().fields[-1]), username=username,
                    password=generate_password_hash(password, method='pbkdf2:sha256'))

    # Add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return ("success", new_user)

@app.route('/api/signup', methods=['POST'])
def api_signup_post():
    (message, new_user) = signup(request)

    if not new_user:
        return jsonify({'success': False, 'error': message})

    return jsonify({'success': True, 'user_id': new_user.userid})

@app.route('/signup', methods=['POST'])
def signup_post():
    (message, new_user) = signup(request)

    if not new_user:
        return message

    login_user(new_user, remember=True)
    return redirect("/edit")

def do_login(request):
    username = request.form.get("username")
    password = request.form.get("password")

    user = User.query.filter_by(username=username).first()

    # Check if the user actually exists
    # Take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not password or not check_password_hash(user.password, password):
        return ("Invalid username or password.", None)

    return ("success", user)

@app.route('/login', methods=['POST'])
def login_post():
    (message, user) = do_login(request)

    if not user:
        return message

    # If the above check passes, then we know the user has the right credentials
    login_user(user, remember=True)
    return redirect("/")

@app.route("/logout", methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect("/")

@app.route('/api/login', methods=['POST'])
def api_login_post():
    (message, user) = do_login(request)

    if not user:
        return jsonify({'success': False, 'error': message})

    return jsonify({'success': True, 'user_id': user.userid})

def save_user_info(request):
    current_user.text = request.form.get("text")
    current_user.hobbies = request.form.get("hobbies")
    current_user.birthday = request.form.get("birthday")
    current_user.school = request.form.get("school")
    current_user.name = request.form.get("name")
    current_user.introduction = request.form.get("introduction")
    db.session.commit()

@app.route('/api/save_user_info', methods=['POST'])
@login_required
def api_save_user_info():
    save_user_info(request)
    return jsonify({'success': True})

@app.route('/save_user_info', methods=['POST'])
@login_required
def web_save_user_info():
    save_user_info(request)
    return redirect("/")

def get_info():
    info = ""
    if current_user.name:
        info += "\nName: " + current_user.name
    if current_user.hobbies:
        info += "\nHobbies: " + current_user.hobbies
    if current_user.school:
        info += "\nSchool: " + current_user.school
    if current_user.text:
        info += "\nText: " + current_user.text
    if current_user.birthday:
        info += "\nBirthday: " + current_user.birthday
    return info

@app.route('/api/send_text', methods=['POST'])
@login_required
def send_text():
    question = request.form.get("question")

    messages = [
        {
            "role": "system",
            "content": "You are a person talking to your peers, here are some information about you:"
        },
        {
            "role": "user",
            "content": get_info()
        },
        {
            "role": "system",
            "content": "The answer should be " + (request.form.get("tone") or "") + " and " + (request.form.get("verbosity") or "") + ". The following is the question."
        },
        {
            "role": "user",
            "content": question
        },
    ]
    if request.form.get("whatYouWantToSay"):
        messages.append({
			"role": "system",
			"content": "The user wants to say " + (request.form.get("whatYouWantToSay") or "")
		})
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages,
        n=3
    )

    messages = [c.message.content for c in completion.choices]

    return jsonify({'success': True, 'answers': messages})

@app.route('/api/generate_introduction', methods=['POST'])
@login_required
def generate_introduction():
    messages = [
        {
            "role": "system",
            "content": "Generate an introduction about yourself. Be concise and include the fact that you are using this app to help you communicate. Here are some information about you:"
        },
        {
            "role": "user",
            "content": get_info()
        }
    ]
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=messages
    )

    messages = [c.message.content for c in completion.choices]

    return jsonify({'success': True, 'answers': messages})

@app.route('/api/save_answer', methods=['POST'])
@login_required
def save_answer():
    chosen_answer = request.form.get("chosen_answer")
    question = request.form.get("question")
    new_answer = Answer(
        answerid=str(uuid.uuid4().fields[-1]),
        userid=current_user.userid,
        question=question,
        chosen_answer=chosen_answer
    )
    db.session.add(new_answer)
    db.session.commit()
    return jsonify({'success': True, 'answer_id': new_answer.answerid})


@app.route('/api/previous_answers')
@login_required
def get_previous_answers():
    previous_answers = Answer.query.filter_by(userid=current_user.userid).order_by(Answer.answerid).all()
    return jsonify([
        {
            'answer_id': a.answerid,
            'question': a.question,
            'chosen_answer': a.chosen_answer
        } for a in previous_answers
    ])

#delete a single history
@app.route('/api/delete_answer', methods=['POST'])
@login_required
def delete_answer():
    answer_id = request.form.get('answer_id')
    if not answer_id:
        return jsonify({'success': False, 'message': 'Answer ID is required.'})

    # Fetch the answer and check if it belongs to the current user
    answer = Answer.query.filter_by(answerid=answer_id, userid=current_user.userid).first()
    if not answer:
        return jsonify({'success': False, 'message': 'Answer not found or unauthorized.'})

    # Delete the answer
    db.session.delete(answer)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Answer deleted successfully.', 'answer_id': answer_id})

# New route to delete chat history
@app.route('/api/delete_chat_history', methods=['POST'])
@login_required
def delete_chat_history():
    # Delete all answers associated with the current user
    Answer.query.filter_by(userid=current_user.userid).delete()
    db.session.commit()
    return jsonify({'success': True, 'message': 'Chat history deleted successfully.'})

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)