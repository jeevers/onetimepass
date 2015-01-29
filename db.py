"""
DB Model and Helper functions to create/get users
"""
from peewee import *
import pyotp

import auth

USERSDB = 'users.db'
db = SqliteDatabase(USERSDB)

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    username = CharField(unique=True)
    email = CharField()
    passwdhash = CharField()
    #otp_enabled = BoolField(default=False)
    otp_secret = CharField()
    hotp_counter = IntegerField(default=0)
    failed_attempts = IntegerField(default=0)

def init_db(tables, database):
    """
    Initializes tables. The tables argument must be a list.
    """
    database.create_tables(tables)

def create_user(username, password, email):
    """
    Adds user to database. The password is hashed using pbkdf2_sha256.
    The otp secret is automatically generated, and needs to be base32 encoded.
    """
    new_user = User(username=username,
              email=email,
              passwdhash=auth.generate_hash(password),
              otp_secret=pyotp.random_base32())
    new_user.save()

def get_user(username):
    """
    Queries database for specified username. Will throw a User.DoesNotExist
    exception if not found. The username field is unique, so
    only one user account will be returned.
    """
    user_query = User.select().where(User.username == username)
    return user_query.get()
