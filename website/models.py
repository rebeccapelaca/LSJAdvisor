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
    other_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    confirmed = db.Column(db.Boolean)
    done = db.Column(db.Boolean)
    ratings = db.relationship('Rating', backref='author', lazy='dynamic')
    rating_done = db.Column(db.Boolean)
    payed = db.Column(db.Boolean)

    author = db.relationship('User', backref='author', foreign_keys=[author_id])
    other = db.relationship('User', backref='other', foreign_keys=[other_user_id])

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
    ad_id = db.Column(db.Integer, db.ForeignKey('ads.id'))
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    object = db.Column(db.String(255))
    read = db.Column(db.Boolean)
    body = db.Column(db.Text)

    sender = db.relationship('User', backref='sent_messages', foreign_keys=[sender_id])
    addressee = db.relationship('User', backref='received_messages', foreign_keys=[addressee_id])
    ad = db.relationship('Ad', backref='ad', foreign_keys=[ad_id])

    def get_id(self):
        return self.id

class Rating(db.Model):
    __tablename__ = 'ratings'
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text)
    vote = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    addressee_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    ad_id = db.Column(db.Integer, db.ForeignKey('ads.id'))

    author_rating = db.relationship('User', backref='author_rating', foreign_keys=[author_id])
    addressee_rating = db.relationship('User', backref='addressee_rating', foreign_keys=[addressee_id])
    ad_rating = db.relationship('Ad', backref='ad_rating', foreign_keys=[ad_id])


    def get_id(self):
        return self.id

    def getAuthorFirstName(self):
        author = User.query.filter_by(id=self.author_id).first()
        return author.first_name

    def getAuthorLastName(self):
        author = User.query.filter_by(id=self.author_id).first()
        return author.last_name