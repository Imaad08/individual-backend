""" database dependencies to support sqliteDB examples """
from random import randrange
from datetime import date
import os, base64
import json

from __init__ import app, db
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash



class User(db.Model):
    __tablename__ = 'users'  

    id = db.Column(db.Integer, primary_key=True)
    _name = db.Column(db.String(255), unique=False, nullable=False)
    _uid = db.Column(db.String(255), unique=True, nullable=False)
    _password = db.Column(db.String(255), unique=False, nullable=False)
    _email = db.Column(db.String(255), unique=True, nullable=False)
    _role = db.Column(db.String(20), default="User", nullable=False)

    def __init__(self, name, uid, email, password="123qwerty", role="User" ):
        self._name = name
        self._uid = uid
        self._email = email
        self.set_password(password)
        self._role = role

    @property
    def role(self):
        return self._role
    
    @role.setter
    def role(self, role):
        self._role = role
        
    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, email):
        self._email = email

    @property
    def name(self):
        return self._name
    
    @name.setter
    def name(self, name):
        self._name = name
    
    @property
    def uid(self):
        return self._uid
    
    @uid.setter
    def uid(self, uid):
        self._uid = uid
        
    def is_uid(self, uid):
        return self._uid == uid
    
    def is_admin(self):
        return self._role == "Admin"
    
    @property
    def password(self):
        return self._password[0:10] + "..." 

    def set_password(self, password):
        """Create a hashed password."""
        if password is not None:
            self._password = generate_password_hash(password, method='pbkdf2:sha256')

    def is_password(self, password):
        """Check against hashed password."""
        result = check_password_hash(self._password, password)
        return result

    def __str__(self):
        return json.dumps(self.read())

    def create(self):
        try:
            db.session.add(self)  
            db.session.commit()  
            return self
        except IntegrityError:
            db.session.remove()
            return None
        
    def read(self):
        return {
            "id": self.id,
            "name": self.name,
            "uid": self.uid,
            "email": self.email,
            "role": self.role,
        }

    def update(self, name="", uid="", password=""):
        """only updates values with length"""
        if len(name) > 0:
            self.name = name
        if len(uid) > 0:
            self.uid = uid
        if len(password) > 0:
            self.set_password(password)
        db.session.commit()
        return self
    

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return None


"""Database Creation and Testing """


def initUsers():
    with app.app_context():
        """Create database and tables"""
        db.create_all()

        """Tester data for table"""
        users_data = [
    {'name': 'Thomas Edison', 'uid': 'toby', 'email': 'thomas@example.com', 'password': '123toby', 'role':'Admin'},
    ]


        for user_data in users_data:
            existing_user = User.query.filter_by(_uid=user_data['uid']).first()

            if existing_user:
                print(f"User with _uid '{user_data['uid']}' already exists. Updating user data.")
                existing_user.update(
                    name=user_data['name'],
                    email=user_data['email'],
                    password=user_data['password'],
                )
            else:
                new_user = User(
                    name=user_data['name'],
                    uid=user_data['uid'],
                    email=user_data['email'],
                    password=user_data['password'],
                )
                db.session.add(new_user)

        db.session.commit()
        
    