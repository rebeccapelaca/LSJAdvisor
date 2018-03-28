import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import LoginManager


app = Flask(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'my secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
# this is the login view users will be redirected to if they are not logged in and they try to access a private page
login_manager.login_view = 'index'

import views
