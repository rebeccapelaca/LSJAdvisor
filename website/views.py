from flask import render_template, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user
from .forms import LoginForm, RegistrationForm
from .models import User

from . import app, db, login_manager

@login_manager.user_loader
def get_user(username):
    '''This is needed by LoginManager to retrieve a User instance based on its ID (in this case, username)'''
    return User.query.filter_by(username=username).first()

@app.before_first_request
def setup_db():
    db.create_all()

@app.route('/', methods=['GET', 'POST'])
def index():
    myForm = LoginForm()
    if myForm.validate_on_submit():
        # we are certain user exists because of the username validator of LoginForm
        user = get_user(myForm.username.data)
        if user.check_password(myForm.password.data):
            # login the user, then redirect to his user page
            login_user(user)
            flash('User logged in!', 'success')
            return redirect(url_for('user'))
        else:
            flash('Incorrect password!', 'danger')

    return render_template('homepage.html', form=myForm)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contacts')
def contacts():
    return redirect(url_for('about'))

@app.route('/user')
@login_required
def user():
    '''You need to be logged in to access this page'''
    return render_template('user.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    username=form.username.data)
        user.password = form.password.data
        db.session.add(user)
        db.session.commit()
        flash('User succesfully registered', 'success')
        return redirect(url_for('index'))

    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('User logged out!', 'success')
    return redirect(url_for('index'))