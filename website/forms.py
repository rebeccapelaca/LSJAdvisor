from flask_wtf import Form
from wtforms import StringField, SubmitField, PasswordField, RadioField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from .models import User

class RegistrationForm(Form):
    first_name = StringField('First name', validators=[DataRequired("Please enter your first name")])
    last_name = StringField('Last name', validators=[DataRequired("Please enter your last name ")])
    email = StringField('Email', validators=[DataRequired("Please enter your Email address"), Length(min=4)])
    password = PasswordField('Password', validators=[DataRequired("Please enter a password"), Length(min=6)])
    password2 = PasswordField('Repeat password',
                              validators=[DataRequired(),
                                          EqualTo('password', message="Please check both passwords match")])
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Email already exists')

class EditProfileForm(Form):
    first_name = StringField('First name', validators=[DataRequired("Please enter your first name")])
    last_name = StringField('Last name', validators=[DataRequired("Please enter your last name ")])
    password_last = PasswordField('Last password',
                                  validators=[DataRequired("Please enter your last password"), Length(min=6)])
    password = PasswordField('New password', validators=[DataRequired("Please enter a new password"), Length(min=6)])
    password2 = PasswordField('Repeat password',
                              validators=[DataRequired(),
                                          EqualTo('password', message="Please check both passwords match")])
    submit = SubmitField('Edit')

class LoginForm(Form):
    email = StringField('Email', validators=[DataRequired("Please enter your Email address")])
    password = PasswordField('Password', validators=[DataRequired("Please enter your password")])
    submit = SubmitField('Login')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Email does not exist')

class WriteForm(Form):

    categories_not_ordered = ['Houseworks', 'Children', 'School', 'Animals', 'Post Office', 'Supermarket']
    zones_not_ordered = ['Crocetta', 'Santa Rita', 'Cenisia', 'San Paolo', 'Cit Turin',
                         'Vanchiglia', 'Barriera Milano', 'Quadrilatero', 'Centro']

    categories_not_ordered.sort()
    zones_not_ordered.sort()

    categories = [(c, c) for c in categories_not_ordered]
    zones = [(a, a) for a in zones_not_ordered]

    title = RadioField(choices=[('I need', 'I need'), ('I offer', 'I offer')],
                       validators=[DataRequired("Please choose a type of ad")])
    body = TextAreaField("Description", validators=[DataRequired("Please enter a short description")])
    category = SelectField(label="Category", choices=categories)
    zone = SelectField(label="Zone", choices=zones)
    submit = SubmitField('Add')

class FindForm(Form):

    categories_not_ordered = ['Houseworks', 'Children', 'School', 'Animals', 'Post Office', 'Supermarket']
    zones_not_ordered = ['Crocetta', 'Santa Rita', 'Cenisia', 'San Paolo', 'Cit Turin',
                         'Vanchiglia', 'Barriera Milano', 'Quadrilatero', 'Centro']

    categories_not_ordered.sort()
    zones_not_ordered.sort()

    categories = [(c, c) for c in categories_not_ordered]
    zones = [(a, a) for a in zones_not_ordered]

    title = RadioField(choices=[('I offer', 'I need'), ('I need', 'I offer')],
                       validators=[DataRequired("Please choose a type of ad")])
    category = SelectField(label="Category", choices=categories, validators=[DataRequired()])
    zone = SelectField(label="Zone", choices=zones, validators=[DataRequired()])
    submit = SubmitField('Find')

class EditForm(Form):

    categories_not_ordered = ['Houseworks', 'Children', 'School', 'Animals', 'Post Office', 'Supermarket']
    zones_not_ordered = ['Crocetta', 'Santa Rita', 'Cenisia', 'San Paolo', 'Cit Turin',
                         'Vanchiglia', 'Barriera Milano', 'Quadrilatero', 'Centro']

    categories_not_ordered.sort()
    zones_not_ordered.sort()

    categories = [(c, c) for c in categories_not_ordered]
    zones = [(a, a) for a in zones_not_ordered]

    title = RadioField(choices=[('I need', 'I need'), ('I offer', 'I offer')],
                       validators=[DataRequired("Please choose a type of ad")])
    body = TextAreaField("Description", validators=[DataRequired("Please enter a short description")])
    category = SelectField(label="Category", choices=categories, validators=[DataRequired()])
    zone = SelectField(label="Zone", choices=zones, validators=[DataRequired()])
    submit = SubmitField('Edit')

class WriteMessage(Form):
    object = StringField("Object", validators=[DataRequired("Please enter an object")])
    body = TextAreaField("Message", validators=[DataRequired("Please enter a message")])
    submit = SubmitField('Send')

class WriteRating(Form):

    votes_not_ordered = ['1', '2', '3', '4', '5']
    votes_not_ordered.sort()
    votes = [(c, c) for c in votes_not_ordered]

    comment = TextAreaField("Comment")
    vote = SelectField(label="Vote", choices=votes, validators=[DataRequired("Please enter a vote")])
    submit = SubmitField('Add rating')
