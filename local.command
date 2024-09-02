cd nosyncfiles/aeaacs 
#python3 -m venv ./
source bin/activate
#pip install openai flask flask-sqlalchemy flask-login
export OPENAI_API_KEY=$(<./getkey)
flask  --app main.py run