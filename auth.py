#  Import necessary modules and packages
# Flask: Web framework for building the application.
# Blueprint: A way to organize and group routes in a Flask application.
# render_template, redirect, url_for, request, flash: Functions for rendering HTML templates, redirecting, handling HTTP requests, and displaying flash messages.
# generate_password_hash, check_password_hash: Functions for securely hashing and checking passwords using Werkzeug.
# User: A model representing a user in the application.
# login_user, logout_user, login_required, current_user, UserMixin: Functions and classes for user authentication and session management.
# struct, hmac, hashlib: Modules for packing integers, generating HMACs, and using cryptographic hash functions.
# starmap, xor: Functions for mapping and XOR operations.
# time: Module for handling time-related operations.
# EmailMessage: Class for creating email messages.
# pyotp: Library for generating OTPs (One-Time Passwords).
# ssl, smtplib: Modules for secure email transmission.
# MIMEText, MIMEMultipart: Classes for constructing email messages.
from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import User
from flask_login import login_user, logout_user, login_required, current_user, UserMixin
from __init__ import db
import hmac
import hashlib
import struct
from operator import xor
from itertools import starmap
import time
from email.message import EmailMessage
import pyotp
import random
import ssl
import smtplib
from hash import sha256
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Create a Flask Blueprint named 'auth' for authentication-related routes
# auth is created as a Flask Blueprint to group authentication-related routes.
auth = Blueprint('auth', __name__)

# Helper function to pack an integer into bytes in big-endian format

_pack_int = struct.Struct('>I').pack

#pbkdf2_hex and pbkdf2_bin functions implement the PBKDF2 algorithm to derive a secure password hash.

# Password-based key derivation function (PBKDF2) for generating a hexadecimal hash
def pbkdf2_hex(data, salt, iterations=1000, keylen=24, hashfunc=None):
    return pbkdf2_bin(data, salt, iterations, keylen, hashfunc).hex()

# Password-based key derivation function (PBKDF2) for generating a binary hash
def pbkdf2_bin(data, salt, iterations=1000, keylen=24, hashfunc=None):
    hashfunc = hashfunc or hashlib.sha256
    mac = hmac.new(data, None, hashfunc)

    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return list(h.digest())

    buf = bytearray()
    for block in range(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        for i in range(iterations - 1):
            u = _pseudorandom(bytes(u))
            rv = list(starmap(xor, zip(rv, u)))
        buf.extend(rv)

    return bytes(buf)[:keylen]

# Function to check if the entered password matches the original password
# check_password function checks if the entered password matches the original password stored in a secure manner.

def check_password(og_password, inp_password):
    salt = b'GroupA11'
    if og_password == pbkdf2_hex(inp_password.encode('utf-8'), salt):
        return True
    else:
        return False

# Route for handling login functionality
# Handles both GET and POST requests.
# Retrieves user input (email, password) from the form.
# Checks if the user exists and if the password is correct.
# Logs in the user, sets a session cookie, and redirects to the profile page.
# Sends a notification email to the user.
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Please sign up before!')
            return redirect(url_for('auth.signup'))
        elif not check_password(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))

        login_user(user, remember=remember)

        # Notify the user via email
        notify(user.email)

        return redirect(url_for('main.profile'))

# Function to send a notification email
# Sends a notification email using Gmail SMTP.
# Uses SSL for secure communication.
# Notifies the user of a successful login activity.
#"465" in the SMTP code refers to the port number used for establishing a connection with the SMTP server over SSL        
def notify(email):
    email_sender = 'sangamganeshbabu03@gmail.com'
    email_password = 'esgp sdoy pwyw zppu'  
    email_receiver = email

    subject = "Notification of Login Activity"
    body = """
    Login successful to the profile.
    If this activity is not by you, please contact the website operators.
    """

    msg = MIMEMultipart()
    msg['From'] = email_sender
    msg['To'] = email_receiver
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, email_password)
            smtp.sendmail(email_sender, email_receiver, msg.as_string())
        return "Email sent successfully!"
    except Exception as e:
        return f"Error sending email: {e}"

# Route for handling user registration
# Handles both GET and POST requests.
# Retrieves user input (email, name, password) from the form.
# Checks if the email already exists, and if not, creates a new user.
# Sends a notification email to the new user.    
    
@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        salt = b'GroupA11'
        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email address already exists')
            return redirect(url_for('auth.signup'))

        # Create a new user and add it to the database; UTF-8 stands for "Unicode Transformation Format – 8-bit.
        new_user = User(email=email, name=name, password=pbkdf2_hex(password.encode('utf-8'), salt))
        db.session.add(new_user)
        db.session.commit()

        # Notify the new user via email
        notify(email)

        return redirect(url_for('auth.login'))

# Route for handling user logout
# Requires the user to be logged in (@login_required decorator).
# Logs out the user, clears the session cookie, and redirects to the index page.    
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
