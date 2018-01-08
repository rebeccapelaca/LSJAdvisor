from datetime import datetime
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    email = db.Column(db.String, nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String, nullable=False)
    ads = db.relationship('Ad', backref='author', lazy='dynamic')
#    ratings = db.relationship('Rating', backref='author', lazy='dynamic')

    def get_id(self):
        return self.email

    @property
    def password(self):
        raise StandardError('Password is write-only')

    @password.setter
    def password(self, value):
        self.password_hash = generate_password_hash(value)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Ad(db.Model):
    __tablename__ = 'ads'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    body = db.Column(db.Text)
    zone = db.Column(db.String(255))
    category = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
#    ratings = db.relationship('Rating', backref='author', lazy='dynamic')

    def get_id(self):
        return self.id

    def get_author_email(self):
        author = User.query.filter_by(id=self.author_id).first()
        return author.email

    def get_author_id(self):
        author = User.query.filter_by(id=self.author_id).first()
        return author.id

    def get_first_name(self):
        author = User.query.filter_by(id=self.author_id).first()
        return author.first_name

    def get_last_name(self):
        author = User.query.filter_by(id=self.author_id).first()
        return author.last_name

class Message(db.Model):
    __tablename__= 'messages'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    addressee_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    object = db.Column(db.String(255))
    read = db.Column(db.Boolean)
    body = db.Column(db.Text)

    sender = db.relationship('User', backref='sent_messages', foreign_keys=[sender_id])
    addressee = db.relationship('User', backref='received_messages', foreign_keys=[addressee_id])

    def get_id(self):
        return self.id

#class Rating(db.Model):
#    __tablename__ = 'ratings'
#    id = db.Column(db.Integer, primary_key=True)
#    comment = db.Column(db.Text)
#    vote = db.Column(db.Integer)
#    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
#    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
#    ad_id = db.Column(db.Integer, db.ForeignKey('ads.id'))

#    def get_id(self):
#        return self.id