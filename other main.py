#!flask/bin/python
from flask import Flask
app = Flask(__name__)
@app.route('/', methods=['GET'])
def get_tasks():
	return "stuff"

if __name__ == '__main__':
    app.run()