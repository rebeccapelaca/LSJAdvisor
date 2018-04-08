import os
from flask_mail import Mail, Message
from flask import render_template, redirect, url_for, flash, abort, request
from flask_login import login_user, login_required, logout_user, current_user
from .forms import LoginForm, RegistrationForm, WriteForm, FindForm, EditForm, WriteMessage, WriteRating, \
    EditProfileForm
from .models import User, Ad, MessageChat, Rating
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer
from . import app, db, login_manager, APP_ROOT

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'lsjadvisor@gmail.com'
app.config['MAIL_PASSWORD'] = 'lsjadvisor2018'
app.config['MAIL_DEFAULT_SENDER'] = 'LSJAdvisor'

mail = Mail(app)

def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt='email-confirm',
            max_age=expiration
        )
    except:
        return False
    return email

@app.route('/confirm/<token>')
def confirm_email(token):
    email = ""
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired', 'danger')
    u = User.query.filter_by(email=email).first_or_404()
    if u.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        u.confirmed = True
        db.session.add(u)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))

@login_manager.user_loader
def get_user(email):
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
        u = User(first_name=form.first_name.data, last_name=form.last_name.data,
                 email=form.email.data, confirmed=False)
        u.password = form.password.data
        db.session.add(u)
        db.session.commit()
        token = generate_confirmation_token(u.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('email.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(u.email, subject, html)
        flash('A confirmation email has been sent via email', 'success')
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        u = get_user(form.email.data)
        if not u.confirmed:
            flash('Please confirm your email address before login', 'danger')
            return redirect(url_for('login'))
        else:
            if u.check_password(form.password.data):
                login_user(u)
                flash('User logged in!', 'success')
                return redirect(url_for('user'))
            else:
                flash('Incorrect password!', 'danger')
    return render_template('login.html', form=form)

@app.route('/user')
@login_required
def user():
    ads_not_completed = Ad.query.filter_by(author=current_user, done=False).order_by(Ad.created_at.desc()).all()
    size_not = len(ads_not_completed)
    ads_completed = Ad.query.filter_by(author=current_user, done=True).order_by(Ad.created_at.desc()).all()
    size = len(ads_completed)
    other_ads_completed = Ad.query.filter_by(other=current_user, confirmed=True).order_by(Ad.created_at.desc()).all()
    size_other = len(other_ads_completed)
    messages_list = MessageChat.query.filter_by(addressee=current_user,
                                                read=False).order_by(MessageChat.created_at.desc()).all()
    messages_number = len(messages_list)
    ratings_list = Rating.query.filter_by(addressee_id=current_user.id).order_by(Rating.created_at.desc()).all()
    size_ratings = len(ratings_list)
    total_votes = 0
    average_votes = 0
    for rating in ratings_list:
        total_votes += rating.vote
    if size_ratings != 0:
        average_votes = "{0:.1f}".format(total_votes/size_ratings)
    return render_template('user.html', ads_not_completed=ads_not_completed, size_not=size_not,
                           ads_completed=ads_completed, size=size, other_ads_completed=other_ads_completed,
                           size_other=size_other, messages_number=messages_number, average_votes=average_votes,
                           size_ratings=size_ratings)

@app.route('/seeRatings', methods=['GET', 'POST'])
def seeRatings():
    ratings_list = Rating.query.filter_by(addressee_id=current_user.id).order_by(Rating.created_at.desc()).all()
    return render_template('ratings.html', ratings_list=ratings_list)

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
        ad = Ad(title=form.title.data, category=form.category.data, body=form.body.data,
                zone=form.zone.data, author=current_user,
                other_user_id=None, done=False, rating_done_one=False,
                rating_done_two=False, payed=False, confirmed=False)
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
        ads = Ad.query.filter_by(title=form.title.data, zone=form.zone.data,
                                 category=form.category.data, done=False,
                                 confirmed=False).order_by(Ad.created_at.desc()).all()
        return render_template('findAd.html', form=form, ads=ads)
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
    ads = Ad.query.filter_by(author=author_ads, done=False).order_by(Ad.created_at.desc()).all()
    size = len(ads)
    return render_template('other_user.html', author_ads=author_ads, ads=ads, size=size)

@app.route('/writeMessage/<int:id>', methods=['GET', 'POST'])
@app.route('/writeMessage/<int:id>/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def writeMessage(id, ad_id):
    form = WriteMessage()
    if form.validate_on_submit():
        addressee = User.query.filter_by(id=id).first()
        message = MessageChat(ad_id=ad_id, sender=current_user, body=form.body.data,
                              addressee=addressee, read=False, object=form.object.data)
        db.session.add(message)
        db.session.commit()
        flash('Message successfully sent!', 'success')
        return redirect(url_for('writeMessage', id=id, ad_id=ad_id))
    return render_template('writeMessage.html', form=form)

@app.route('/messages')
@login_required
def messages():
    received = MessageChat.query.filter_by(addressee_id=current_user.id).order_by(MessageChat.created_at.desc()).all()
    sent = MessageChat.query.filter_by(sender_id=current_user.id).order_by(MessageChat.created_at.desc()).all()
    size_msg_received = len(received)
    size_msg_sent = len(sent)
    return render_template('messages.html', received=received, sent=sent,
                           size_msg_received=size_msg_received, size_msg_sent=size_msg_sent)

@app.route('/markAsRead/<int:id>')
@login_required
def markAsRead(id):
    msg = MessageChat.query.get_or_404(id)
    msg.read = True
    db.session.add(msg)
    db.session.commit()
    return redirect(url_for('messages'))

@app.route('/deleteMessage/<int:id>', methods=['GET', 'POST'])
@login_required
def deleteMessage(id):
    msg = MessageChat.query.get_or_404(id)
    db.session.delete(msg)
    db.session.commit()
    flash('The message has been removed', 'success')
    return redirect(url_for('messages'))

@app.route('/confirm/<int:ad_id>')
@app.route('/confirm/<int:ad_id>/<int:other_id>', methods=['GET', 'POST'])
@login_required
def confirm(ad_id, other_id):
    ad = Ad.query.get_or_404(ad_id)
    ad.confirmed = True
    ad.rating_done = False
    ad.other_user_id = other_id
    db.session.add(ad)
    db.session.commit()
    flash('The job has been confirmed', 'success')
    return redirect(url_for('messages'))

@app.route('/markAsDone/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def markAsDone(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    ad.done = True
    ad.rating_done = False
    db.session.add(ad)
    db.session.commit()
    flash('The ad has been marked as done', 'success')
    return redirect(url_for('user'))

@app.route('/markAsPayed/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def markAsPayed(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    ad.payed = True
    ad.rating_done = False
    db.session.add(ad)
    db.session.commit()
    flash('The ad has been marked as payed', 'success')
    return redirect(url_for('user'))

@app.route('/addRatingOne/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def addRatingOne(ad_id):
    form = WriteRating()
    if form.validate_on_submit():
        ad = Ad.query.get_or_404(ad_id)
        rating = Rating(ad_id=ad_id, author_id=current_user.id, addressee_id=ad.author_id,
                        comment=form.comment.data, vote=form.vote.data)
        ad.rating_done_one = True
        db.session.add(rating)
        db.session.add(ad)
        db.session.commit()
        flash('Rating successfully added!', 'success')
    return render_template('writeRating.html', form=form)

@app.route('/addRatingTwo/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def addRatingTwo(ad_id):
    form = WriteRating()
    if form.validate_on_submit():
        ad = Ad.query.get_or_404(ad_id)
        rating = Rating(ad_id=ad_id, author_id=current_user.id, addressee_id=ad.other_user_id,
                        comment=form.comment.data, vote=form.vote.data)
        ad.rating_done_two = True
        db.session.add(rating)
        db.session.add(ad)
        db.session.commit()
        flash('Rating successfully added!', 'success')
    return render_template('writeRating.html', form=form)

@app.route('/editProfile',methods=['GET', 'POST'])
@login_required
def editProfile():
    profile = User.query.get_or_404(current_user.id)
    form = EditProfileForm()
    if form.validate_on_submit():
        profile.first_name = form.first_name.data
        profile.last_name = form.last_name.data
        if check_password_hash(profile.password_hash, form.password_last.data):
            profile.password_hash = generate_password_hash(form.password.data)
            db.session.add(profile)
            db.session.commit()
            flash('The profile has been updated', 'success')
            return redirect(url_for('editProfile'))
        else:
            flash('The last password is not correct', 'warning')
    form.first_name.data = profile.first_name
    form.last_name.data = profile.last_name
    return render_template('editProfile.html', form=form)

def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER'])
    mail.send(msg)

@app.route('/upload')
def upload():
    return render_template("upload.html")

@app.route('/upload_image/<email>', methods=["POST"])
def upload_image(email):
    target = os.path.join(APP_ROOT, "static")
    if not os.path.isdir(target):
        os.mkdir(target)
    for f in request.files.getlist("file"):
        destination = "/".join([target, email])
        f.save(destination)
        flash('The photo has been uploaded', 'success')
    return render_template("homepage.html")
