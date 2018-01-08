from flask import render_template, redirect, url_for, flash, abort
from flask_login import login_user, login_required, logout_user, current_user
from .forms import LoginForm, RegistrationForm, WriteForm, FindForm, EditForm, WriteMessage
from .models import User, Ad, Message

from . import app, db, login_manager

@login_manager.user_loader
def get_user(email):
    '''This is needed by LoginManager to retrieve a User instance based on its ID (in this case, username)'''
    return User.query.filter_by(email=email).first()

@app.before_first_request
def setup_db():
    db.create_all()

@app.route('/')
def index():
    return render_template('homepage.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    email=form.email.data)
        user.password = form.password.data
        db.session.add(user)
        db.session.commit()
        flash('User succesfully registered', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # we are certain user exists because of the username validator of LoginForm
        user = get_user(form.email.data)
        if user.check_password(form.password.data):
            # login the user, then redirect to his user page
            login_user(user)
            flash('User logged in!', 'success')
            return redirect(url_for('user'))
        else:
            flash('Incorrect password!', 'danger')

    return render_template('login.html', form=form)

@app.route('/user')
@login_required
def user():
    ads = Ad.query.filter_by(author=current_user).order_by(Ad.created_at.desc()).all()
    size = len(ads)
    return render_template('user.html', ads=ads, size=size)

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('User logged out!', 'success')
    return redirect(url_for('index'))

def datetimeformat(value, format='%B %d, %Y %I:%M:%S %Z'):
    return value.strftime(format)

app.jinja_env.filters['datetimeformat'] = datetimeformat

@app.route('/writeAd', methods=['GET', 'POST'])
def writeAd():
    form = WriteForm()
    if form.validate_on_submit():
        ad = Ad(title=form.title.data, category=form.category.data, body=form.body.data,\
                    zone=form.zone.data,author=current_user._get_current_object())
        db.session.add(ad)
        db.session.commit()
        flash('Ad successfully added!', 'success')
    ads = Ad.query.order_by(Ad.created_at.desc()).all()
    return render_template('writeAd.html', form=form, ads=ads)

@app.route('/findAd', methods=['GET', 'POST'])
@login_required
def findAd():
    form = FindForm()
    ads = []
    if form.validate_on_submit():
        ads = Ad.query.filter_by(title=form.title.data, zone=form.zone.data, category=form.category.data)\
                .order_by(Ad.created_at.desc()).all()
    return render_template('findAd.html', form=form, ads=ads)

@app.route('/editAd/<int:id>', methods=['GET', 'POST'])
@login_required
def editAd(id):
    ad = Ad.query.get_or_404(id)
    if current_user.id != ad.author_id:
        abort(403)
    form = EditForm()
    if form.validate_on_submit():
        ad.title = form.title.data
        ad.body = form.body.data
        ad.category = form.category.data
        ad.zone = form.zone.data
        db.session.add(ad)
        db.session.commit()
        flash('The ad has been updated', 'success')
        return redirect(url_for('writeAd', id=id))
    form.title.data = ad.title
    form.body.data = ad.body
    form.category.data = ad.category
    form.zone.data = ad.zone
    return render_template('editAd.html', form=form, ad=ad)

@app.route('/deleteAd/<int:id>', methods=['GET', 'POST'])
@login_required
def deleteAd(id):
    ad = Ad.query.get_or_404(id)
    if current_user.id != ad.author_id:
        abort(403)
    db.session.delete(ad)
    db.session.commit()
    flash('The ad has been removed', 'success')
    return redirect(url_for('user'))

@app.route('/other_user/<int:id>', methods=['GET', 'POST'])
@login_required
def other_user(id):
    author_ads = User.query.filter_by(id=id).first()
    ads = Ad.query.filter_by(author=author_ads).order_by(Ad.created_at.desc()).all()
    size = len(ads)
    return render_template('other_user.html', author_ads=author_ads, ads=ads, size=size)

@app.route('/writeMessage/<int:id>', methods=['GET', 'POST'])
@login_required
def writeMessage(id):
    form = WriteMessage()
    if form.validate_on_submit():
        addressee = User.query.filter_by(id=id).first()
        message = Message(sender=current_user._get_current_object(), body=form.body.data, addressee=addressee, read=False, object=form.object.data)
        db.session.add(message)
        db.session.commit()
        flash('Message successfully sent!', 'success')
    return render_template('writeMessage.html', form=form)

@app.route('/messages')
@login_required
def messages():
    received = Message.query.filter_by(addressee_id=current_user.id).all()
    sent = Message.query.filter_by(sender_id=current_user.id).all()
    size_msg_received = len(received)
    size_msg_sent = len(sent)
    return render_template('messages.html', received=received, sent=sent, size_msg_received=size_msg_received, size_msg_sent=size_msg_sent)

@app.route('/checkRead/<int:id>')
@login_required
def checkRead(id):
    msg = Message.query.get_or_404(id)
    msg.read = True
    db.session.add(msg)
    db.session.commit()
    return redirect(url_for('messages'))