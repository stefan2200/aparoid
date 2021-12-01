"""
Create the flask application
"""
import sys
import logging
from urllib.parse import quote_plus
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

logging.basicConfig(level=logging.DEBUG if "-q" not in sys.argv else logging.INFO)
logging.getLogger("passlib").setLevel(level=logging.INFO)
logging.getLogger("hpack").setLevel(level=logging.INFO)
logging.getLogger("kafka").setLevel(level=logging.INFO)

flask = Flask(__name__)
flask.config['SQLALCHEMY_DATABASE_URI'] = Config.database_connector
flask.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
flask.jinja_env.filters['quote_plus'] = lambda u: quote_plus(u)
db = SQLAlchemy(flask)
