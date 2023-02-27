from flask import Flask, request
from flask_restful import Resource, Api, reqparse

app = Flask(__name__)

@app.route('/')
def index():
    return {'data':'Hello World!'}

if __name__ == '__main__':
    app.run('0.0.0.0', debug=True)