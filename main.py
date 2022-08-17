from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, abort
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import smtplib
import os
from dotenv import load_dotenv

# Environment Variables
load_dotenv("D:\Python\EnvironmentVariables\.env.txt")

MY_EMAIL = os.getenv("Email")
# Password third app from google
PASSWORD = os.getenv("PASSWORD")
TO_EMAIL = os.getenv("Email")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("Flask_KEY")
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO POSTGREE
URI = os.getenv("DATABASE_URL")  # or other relevant config var
if URI.startswith("postgres://"):
    URI = URI.replace("postgres://", "postgresql://", 1)

## Connect to Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        # If user is not authenticated or id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        # Otherwise, continue with the route function
        return function(*args, **kwargs)
    return decorated_function


##CONFIGURE TABLES
class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False, unique=True)
    map_url = db.Column(db.String(250), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    seats = db.Column(db.String(250))
    coffee_price = db.Column(db.String(250))

    # Optional: this will allow each cafe object to be identified by its name when printed.
    def __repr__(self):
        return f'<Cafe {self.name}>'


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))


# Just use when creating the tables
# db.create_all()

# all Flask routes below
@app.route('/')
def home():
    # pull the data from all the cafes from the database
    all_coffees = Cafe.query.order_by(Cafe.id).all()
    db.session.commit()
    return render_template("index.html", cafes=all_coffees)


@app.route("/cafe/<int:cafe_id>")
def show_cafe(cafe_id):
    # pull the data from the requested cafe from the database
    requested_cafe = Cafe.query.get(cafe_id)
    db.session.commit()
    return render_template("cafe.html", cafe=requested_cafe)


@app.route("/add", methods=["GET", "POST"])
# Using POST to add a new cafe to the database
def add_cafe():
    if request.method == 'POST':
        cafe_name = request.form['name']
        map_url = request.form['map_url']
        img_url = request.form['img_url']
        location = request.form['location']
        has_sockets = bool(request.form.get('has_sockets'))
        has_toilet = bool(request.form.get('has_toilet'))
        has_wifi = bool(request.form.get('has_wifi'))
        can_take_calls = bool(request.form.get('can_take_calls'))
        seats = request.form['seats']
        coffee_price = request.form['coffee_price']

        new_cafe = Cafe(name=cafe_name.upper(),
                        map_url=map_url,
                        img_url=img_url,
                        location=location,
                        has_sockets=has_sockets,
                        has_toilet=has_toilet,
                        has_wifi=has_wifi,
                        can_take_calls=can_take_calls,
                        seats=seats,
                        coffee_price=coffee_price)
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("add_cafe.html")


@app.route("/delete/<int:cafe_id>")
# Just the admin can delete a cafe
@admin_only
def delete_cafe(cafe_id):
    cafe_to_delete = Cafe.query.get(cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/register", methods=["GET", "POST"])
def register():
    # Register a new user, using POST to add the user to the database
    if request.method == 'POST':
        # If user's email already exists
        if User.query.filter_by(email=request.form['register-email']).first():
            # Send flash message
            flash("You've already signed up with that email, log in instead!")
            # Redirect to /login route.
            return redirect(url_for('home'))

        # Use hash and salt to better security
        hash_and_salted_password = generate_password_hash(
            password=request.form['register-password'],
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form['register-email'],
            password=hash_and_salted_password,
            name=request.form['register-name'],
        )
        db.session.add(new_user)
        db.session.commit()

        # This line will authenticate the user with Flask-Login
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template("register.html", current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
# Using POST to check the user login info with the data in the database
def login():
    error = None
    if request.method == "POST":
        email = request.form['login-email']
        password = request.form['login-password']
        # Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if not user:
            # Send flash message
            flash('That email does not exist, please try again.', category='error')
            return redirect(url_for('login'))
        # Check stored password hash against entered password hashed.
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again!", category="error")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", current_user=current_user)


@app.route('/logout')
# Logout user
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/contact', methods=["GET", "POST"])
def contact():
    # Get the data from the contact form and send an email with the send_email function
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        send_email(name, email, message)
        return render_template("index.html", msg_sent=True)
    return render_template("index.html", msg_sent=False)


# Using SMTPlib to send an email by the contact feature
def send_email(name, email, message):
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        connection.starttls()
        connection.login(MY_EMAIL, PASSWORD)
        connection.sendmail(
            from_addr=MY_EMAIL,
            to_addrs=TO_EMAIL,
            msg=f"Subject: Customer\n\nName: {name}\nEmail: {email}\nMessage: {message}"
        )


if __name__ == '__main__':
    app.run(debug=True)
