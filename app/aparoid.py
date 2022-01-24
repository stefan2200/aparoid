"""
Import the controllers and run the database migration
"""
import time
from sqlalchemy.exc import OperationalError
from app import flask, db
from app.controllers import *
try:
    db.create_all()
except OperationalError:
    print("Unable to create database tables, retrying in 10 seconds")
    time.sleep(10)
    db.create_all()

except Exception:
    pass