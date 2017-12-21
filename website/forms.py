from flask_wtf import Form
from wtforms import StringField, IntegerField, SubmitField, PasswordField, RadioField, SelectField, TextAreaField
from wtforms.validators import DataRequired, NumberRange, Length, EqualTo, ValidationError
from .models import User

class RegistrationForm(Form):
    first_name = StringField('First name', validators=[DataRequired()])
    last_name = StringField('Last name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Length(min=4)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Email already exists')


class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Email does not exist')

class WriteForm(Form):

    categories_not_ordered = ['Houseworks', 'Children', 'School', 'Animals', 'Post Office', 'Supermarket']
    zones_not_ordered = ['Crocetta', 'Santa Rita', 'Cenisia', 'San Paolo', 'Cit Turin', 'Vanchiglia', 'Barriera Milano', 'Quadrilatero', 'Centro']

    categories_not_ordered.sort()
    zones_not_ordered.sort()

    categories = [(c, c) for c in categories_not_ordered]
    zones = [(a, a) for a in zones_not_ordered]

    title = RadioField(choices=[('I need', 'I need'), ('I offer', 'I offer')], validators=[DataRequired()])
    body = TextAreaField("Description", validators=[DataRequired()])
    category = SelectField(label="Category", choices=categories)
    zone = SelectField(label="Zone", choices=zones)
    submit = SubmitField('Add')

class FindForm(Form):

    categories_not_ordered = ['Houseworks', 'Children', 'School', 'Animals', 'Post Office', 'Supermarket']
    zones_not_ordered = ['Crocetta', 'Santa Rita', 'Cenisia', 'San Paolo', 'Cit Turin', 'Vanchiglia', 'Barriera Milano', 'Quadrilatero', 'Centro']

    categories_not_ordered.sort()
    zones_not_ordered.sort()

    categories = [(c, c) for c in categories_not_ordered]
    zones = [(a, a) for a in zones_not_ordered]

    title = RadioField(choices=[('I offer','I need'),('I need', 'I offer')], validators=[DataRequired()])
    category = SelectField(label="Category", choices=categories, validators=[DataRequired()])
    zone = SelectField(label="Zone", choices=zones, validators=[DataRequired()])
    submit = SubmitField('Find')

class EditForm(Form):

    categories_not_ordered = ['Houseworks', 'Children', 'School', 'Animals', 'Post Office', 'Supermarket']
    zones_not_ordered = ['Crocetta', 'Santa Rita', 'Cenisia', 'San Paolo', 'Cit Turin', 'Vanchiglia', 'Barriera Milano', 'Quadrilatero', 'Centro']

    categories_not_ordered.sort()
    zones_not_ordered.sort()

    categories = [(c, c) for c in categories_not_ordered]
    zones = [(a, a) for a in zones_not_ordered]

    title = RadioField(choices=[('I need', 'I need'), ('I offer', 'I offer')], validators=[DataRequired()])
    body = TextAreaField("Description", validators=[DataRequired()])
    category = SelectField(label="Category", choices=categories, validators=[DataRequired()])
    zone = SelectField(label="Zone", choices=zones, validators=[DataRequired()])
    submit = SubmitField('Edit')

class WriteRating(Form):

    votes_not_ordered = ['1','2','3','4','5']
    votes_not_ordered.sort()
    votes = [(c, c) for c in votes_not_ordered]

    comment = TextAreaField("Comment")
    vote = SelectField(label="Vote", choices=votes, validators=[DataRequired()])
    submit = SubmitField('Add rating')
