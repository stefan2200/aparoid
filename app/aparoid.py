"""
Import the controllers and run the database migration
"""
from app import flask, db
from app.controllers import *
try:
    db.create_all()
except Exception:
    pass
