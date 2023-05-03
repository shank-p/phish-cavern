from flask import Flask, jsonify
from flask_restful import Resource, Api, reqparse, abort
from flask_sqlalchemy import SQLAlchemy

from feature_extractor import URL_Features

import sqlite3
import time
import pprint

DATABASE = 'db.sqlite'

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DATABASE
db = SQLAlchemy(app)
api = Api(app)

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
    status = db.Column(db.String)

    def __repr__(self) -> str:
        return self.url
    

post_args = reqparse.RequestParser()
post_args.add_argument("url", type=str, help='url is a required field.', required=True)

class Process(Resource):
    def get(self):
        return {'data':'Hello World'}
    
    def post(self):
        args = post_args.parse_args()
        ip_url = args['url']
        print(ip_url, sep='\n')
        
        op = Url_Data.query.filter_by(url=ip_url).first()
        if op:
            pass
        else:
            url_features = URL_Features(ip_url)
            url_features.features['status'] = 'Legitimate'
            url_data = Url_Data( **url_features.features)
            db.session.add(url_data)
            db.session.commit()
        
        # return pre-set json data as example 
        op = {
            "url": "https://en.wikipedia.org/wiki/Gateway",
            "length_url": 37,
            "length_hostname": 16,
            "ip": 0,
            "nb_dots": 2,
            "nb_hyphens": 0,
            "nb_at": 0,
            "nb_qm": 0,
            "nb_and": 0,
            "nb_or": 0,
            "nb_eq": 0,
            "nb_underscore": 0,
            "nb_tilde": 0,
            "nb_percent": 0,
            "nb_slash": 4,
            "nb_star": 0,
            "nb_colon": 1,
            "nb_comma": 0,
            "nb_semicolumn": 0,
            "nb_dollar": 0,
            "nb_space": 0,
            "nb_www": 0,
            "nb_com": 0,
            "nb_dslash": 0,
            "http_in_path": 0,
            "https_token": 0,
            "ratio_digits_url": 0,
            "ratio_digits_host": 0,
            "punycode": 0,
            "port": 0,
            "tld_in_path": 0,
            "tld_in_subdomain": 0,
            "abnormal_subdomain": 0,
            "nb_subdomains": 2,
            "prefix_suffix": 0,
            "random_domain": 0,
            "shortening_service": 0,
            "path_extension": 0,
            "nb_redirection": 0,
            "nb_external_redirection": 0,
            "length_words_raw": 4,
            "char_repeat": 0,
            "shortest_words_raw": 2,
            "shortest_word_host": 2,
            "shortest_word_path": 4,
            "longest_words_raw": 9,
            "longest_word_host": 9,
            "longest_word_path": 7,
            "avg_words_raw": 5.5,
            "avg_word_host": 5.5,
            "avg_word_path": 5.5,
            "phish_hints": 0,
            "domain_in_brand": 1,
            "brand_in_subdomain": 0,
            "brand_in_path": 0,
            "suspecious_tld": 0,
            "statistical_report": 0,
            "nb_hyperlinks": 199,
            "ratio_intHyperlinks": 0.964824121,
            "ratio_extHyperlinks": 0.035175879,
            "ratio_nullHyperlinks": 0,
            "nb_extCSS": 0,
            "ratio_intRedirection": 0,
            "ratio_extRedirection": 0.428571429,
            "ratio_intErrors": 0,
            "ratio_extErrors": 0,
            "login_form": 0,
            "external_favicon": 0,
            "links_in_tags": 100,
            "submit_email": 0,
            "ratio_intMedia": 100,
            "ratio_extMedia": 0,
            "sfh": 0,
            "iframe": 0,
            "popup_window": 0,
            "safe_anchor": 74.07407407,
            "onmouseover": 0,
            "right_clic": 0,
            "empty_title": 0,
            "domain_in_title": 0,
            "domain_with_copyright": 0,
            "whois_registered_domain": 0,
            "domain_registration_length": 902,
            "domain_age": 7133,
            "web_traffic": 12,
            "dns_record": 0,
            "google_index": 0,
            "page_rank": 7,
            "status": "legitimate"
        }

        response = jsonify(op)
        response.status_code = 200
        return response

api.add_resource(Process, '/api')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)