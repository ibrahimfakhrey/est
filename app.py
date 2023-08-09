from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager 
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, TextAreaField
from wtforms.validators import InputRequired, Length
from flask_wtf.file import FileField, FileAllowed
from flask_uploads import IMAGES
from flask import render_template, redirect, url_for, request, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import login_required, login_user, current_user, logout_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
app = Flask(__name__)

photos = UploadSet('photos', IMAGES)

app.config['UPLOADED_PHOTOS_DEST'] = 'images'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///engage.db'
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'ksdlfkdsofidsithnaljnfadksjhfdskjfbnjewrhewuirhfsenfdsjkfhdksjhfdslfjasldkj'

login_manager = LoginManager(app)
login_manager.login_view = 'login'

configure_uploads(app, photos)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
SQLALCHEMY_TRACK_MODIFICATIONS = False

@app.template_filter('time_since')
def time_since(delta):

    seconds = delta.total_seconds()

    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)

    if days > 0:
        return '%dd' % (days)
    elif hours > 0:
        return '%dh' % (hours)
    elif minutes > 0:
        return '%dm' % (minutes)
    else:
        return 'Just now'

class RegisterForm(FlaskForm):
    name = StringField('Full name', validators=[InputRequired('A full name is required.'), Length(max=100, message='Your name can\'t be more than 100 characters.')])
    username = StringField('Username', validators=[InputRequired('Username is required.'), Length(max=30, message='Your username is too many characters.')])
    phone = StringField('Username', validators=[InputRequired('Username is required.'), Length(max=30, message='Your phone is too many characters.')])

    password = PasswordField('Password', validators=[InputRequired('A password is required.')])
    image = FileField(validators=[FileAllowed(IMAGES, 'Only images are accepted.')])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired('Username is required.'), Length(max=30, message='Your username is too many characters.')])
    password = PasswordField('Password', validators=[InputRequired('A password is required.')])
    remember = BooleanField('Remember me')

class TweetForm(FlaskForm):
    text = TextAreaField('Message', validators=[InputRequired('Message is required.')])
manager = Manager(app)
manager.add_command('db', MigrateCommand)

followers = db.Table('follower',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('followee_id', db.Integer, db.ForeignKey('user.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    username = db.Column(db.String(30),unique=True)
    phone = db.Column(db.String(100), unique=True)
    image = db.Column(db.String(100))
    password = db.Column(db.String(50))
    join_date = db.Column(db.DateTime)

    tweets = db.relationship('Tweet', backref='user', lazy='dynamic')

    following = db.relationship('User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followee_id == id),
        backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    followed_by = db.relationship('User',  secondary=followers,
        primaryjoin=(followers.c.followee_id == id),
        secondaryjoin=(followers.c.follower_id == id),
        backref=db.backref('followees', lazy='dynamic'), lazy='dynamic')

class Tweet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.String(140))
    date_created = db.Column(db.DateTime)
db.create_all()
class MyModelView(ModelView):
    def is_accessible(self):

            return True




admin = Admin(app)
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Tweet  , db.session))
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    form = LoginForm()

    return render_template('index.html', form=form, logged_in_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if not user:
            return render_template('index.html', form=form, message='Login Failed!')

        if check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)

            return redirect(url_for('profile'))

        return render_template('index.html', form=form, message='Login Failed!')

    return render_template('index.html', form=form)

@app.route('/profile', defaults={'username' : None})
@app.route('/profile/<username>')
def profile(username):

    if username:
        user = User.query.filter_by(username=username).first()
        if not user:
            abort(404)
    else:
        user = current_user

    tweets = Tweet.query.filter_by(user=user).order_by(Tweet.date_created.desc()).all()

    current_time = get_current_time()

    followed_by = user.followed_by.all()

    display_follow = True

    if current_user == user:
        display_follow = False
    elif current_user in followed_by:
        display_follow = False

    who_to_watch = who_to_watch_list(user)

    return render_template('profile.html', current_user=user, tweets=tweets, current_time=current_time, followed_by=followed_by, display_follow=display_follow, who_to_watch=who_to_watch, logged_in_user=current_user)

def who_to_watch_list(user):
    return User.query.filter(User.id != user.id).order_by(db.func.random()).limit(4).all()

def get_current_time():
    return datetime.now()

@app.route('/timeline', defaults={'username' : None})
@app.route('/timeline/<username>')
def timeline(username):
    form = TweetForm()

    if username:
        user = User.query.filter_by(username=username).first()
        if not user:
            abort(404)

        tweets = Tweet.query.all()
        total_tweets = len(tweets)

    else:
        user = current_user
        # tweets = Tweet.query.join(followers, (followers.c.followee_id == Tweet.user_id)).filter(followers.c.follower_id == current_user.id).order_by(Tweet.date_created.desc()).all()
        tweets = Tweet.query.all()

        total_tweets = Tweet.query.filter_by(user=user).order_by(Tweet.date_created.desc()).count()

    current_time = get_current_time()

    followed_by_count = user.followed_by.count()

    who_to_watch = who_to_watch_list(user)
    print(tweets)

    return render_template('timeline.html', form=form, tweets=tweets, current_time=current_time, current_user=user, total_tweets=total_tweets, who_to_watch=who_to_watch, logged_in_user=current_user, followed_by_count=followed_by_count)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/post_tweet', methods=['POST'])
@login_required
def post_tweet():
    form = TweetForm()

    if form.validate():
        tweet = Tweet(user_id=current_user.id, text=form.text.data, date_created=datetime.now())
        db.session.add(tweet)
        db.session.commit()

        return redirect(url_for('timeline'))

    return 'Something went wrong.'

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        image_filename = photos.save(form.image.data)
        image_url = photos.url(image_filename)

        new_user = User(name=form.name.data, phone=form.phone.data,username=form.username.data, image=image_url, password=generate_password_hash(form.password.data), join_date=datetime.now())
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for('profile'))

    return render_template('register.html', form=form)

@app.route('/follow/<username>')
@login_required
def follow(username):
    user_to_follow = User.query.filter_by(username=username).first()

    current_user.following.append(user_to_follow)

    db.session.commit()

    return redirect(url_for('profile'))
@app.route("/exams")
def exams():
    return render_template("test.html",logged_in_user=current_user)
if __name__ == '__main__':
    print("done")
    app.run(debug=True)
