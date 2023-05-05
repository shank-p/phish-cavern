from flask import Flask, jsonify, request
from flask_restful import Resource, Api, reqparse, abort
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

from feature_extractor import URL_Features
from tensorflow.keras.models import load_model

import numpy as np

import sqlite3
import time
import pprint

DATABASE = 'db.sqlite'

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DATABASE
db = SQLAlchemy(app)
api = Api(app)
cors = CORS(app)

class Url_Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, unique=True, nullable=False)
    url_length = db.Column(db.Integer)
    hostname_length = db.Column(db.Integer)
    is_ip = db.Column(db.Integer)
    count_dots = db.Column(db.Integer)
    count_hyphens = db.Column(db.Integer)
    count_at = db.Column(db.Integer)
    count_question_mark = db.Column(db.Integer)
    count_and = db.Column(db.Integer)
    count_equals = db.Column(db.Integer)
    count_underscore = db.Column(db.Integer)
    count_percentage = db.Column(db.Integer)
    count_slash = db.Column(db.Integer)
    count_www = db.Column(db.Integer)
    http_in_path = db.Column(db.Integer)
    https_token = db.Column(db.Integer)
    ratio_digits_url = db.Column(db.Numeric(6, 2))
    count_subdomains = db.Column(db.Integer)
    prefix_sufix = db.Column(db.Integer)
    count_hyperlinks = db.Column(db.Integer)
    ratio_int_hyperlinks = db.Column(db.Numeric(6, 2))
    ratio_ext_hyperlinks = db.Column(db.Numeric(6, 2))
    ext_favicon = db.Column(db.Integer)
    links_in_tags = db.Column(db.Numeric(6, 2))
    iframe = db.Column(db.Integer)
    safe_anchor = db.Column(db.Numeric(6, 2))
    whois_reg = db.Column(db.Integer)
    domain_reg_len = db.Column(db.Integer)
    domain_age = db.Column(db.Integer)
    similarweb_rank = db.Column(db.Integer)
    status = db.Column(db.Numeric(6, 2))

    def __repr__(self) -> str:
        return self.url
    

post_args = reqparse.RequestParser()
post_args.add_argument("url", type=str, help='url is a required field.', required=True)

# def predict_classes(model, x):
#     proba = model.predict(x)
#     if proba.shape[-1] > 1:
#         return proba.argmax(axis=-1)
#     else:
#         return (proba > 0.5).astype('int32')

class Process(Resource):
    def get(self):
        return {'data':'Hello World'}
    
    def post(self):
        args = post_args.parse_args()
        ip_url = args['url']
        print('-> Received URL:', ip_url)
        
        op = Url_Data.query.filter_by(url=ip_url).first()
        if op:
            pass
        else:
            url_features = URL_Features(ip_url)
            print(url_features.features, sep='\n')

            domain_features = np.array([
                url_features.features['url_length'],
                url_features.features['hostname_length'],
                url_features.features['is_ip'],
                url_features.features['count_dots'],
                url_features.features['count_hyphens'],
                url_features.features['count_at'],
                url_features.features['count_question_mark'],
                url_features.features['count_and'],
                url_features.features['count_equals'],
                url_features.features['count_underscore'],
                url_features.features['count_percentage'],
                url_features.features['count_slash'],
                url_features.features['count_www'],
                url_features.features['http_in_path'],
                url_features.features['https_token'],
                url_features.features['ratio_digits_url'],
                url_features.features['count_subdomains'],
                url_features.features['prefix_sufix'],
                url_features.features['whois_reg'],
                url_features.features['domain_reg_len'],
                url_features.features['domain_age']
            ])

            html_features = np.array([
                url_features.features['count_hyperlinks'],
                url_features.features['ratio_int_hyperlinks'],
                url_features.features['ratio_ext_hyperlinks'],
                url_features.features['ext_favicon'],
                url_features.features['links_in_tags'],
                url_features.features['iframe'],
                url_features.features['safe_anchor']
            ])

            # print('domain', domain_features)
            # print('html', html_features)

            processed_data = [html_features, domain_features]
            # print('processed_data',processed_data)
            processed_data = [np.expand_dims(x, axis=0) for x in processed_data]
            # print('expanded_data', processed_data)
            output_prediction = model.predict(processed_data)
            # print('output_pred:', output_prediction)
            # output = predict_classes(model, processed_data)
            # print('op:',output)

            url_features.features['status'] = output_prediction
            url_data = Url_Data( **url_features.features)
            db.session.add(url_data)
            db.session.commit()

        data = Url_Data.query.filter_by(url=ip_url).first()
        op = {
            'url' : data.url,
            'url-scheme': data.https_token,
            'domain-reg': True if data.whois_reg != 0 else False,
            'domain-age': data.domain_age,
            'webpage-rank': data.similarweb_rank,
            'status': data.status
        }
        
        # return pre-set json data as example 
        response = jsonify(op)
        response.status_code = 200
        return response

api.add_resource(Process, '/api')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    try:
        model = load_model('ModC.h5')
        print(" ******* Model Load Successful. ******")
    except:
        print('Model Load Failed!')
    app.run(host='0.0.0.0', debug=True)