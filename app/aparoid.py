"""
Import the controllers and run the database migration
"""
from app import flask, db
from app.controllers import *

db.create_all()
