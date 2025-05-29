#!/usr/bin/env python
import cv2
import json
import numpy as np
import classifier
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)
import sqlite3
import contextlib
import re
import numpy as np
import pickle
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)
import os 
from create_database import setup_database
from utils import login_required, set_session
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import os 
from create_database import setup_database
from utils import login_required, set_session
from flask import Flask, render_template,  request
from keras.models import model_from_json

app = Flask(__name__)

app.secret_key = 'xpSm7p5bgJY8rNoBjGWiz5yjxM-NEBlW6SIBI62OkLc='

database = "users.db"
setup_database(name=database)

app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0


# Load Haarcascade File
face_detector = cv2.CascadeClassifier("ml_folder/haarcascade_frontalface_default.xml")

# Load the Model and Weights
model = model_from_json(open("ml_folder/facial_expression_model_structure.json", "r").read())
model.load_weights('ml_folder/facial_expression_model_weights.h5')
model.make_predict_function()



@app.route('/')
def first():
    return render_template('index1.html')

@app.route('/logout')
def logout():
    session.clear()
    session.permanent = False
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Set data to variables
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Attempt to query associated user data
    query = 'select username, password, email from users where username = :username'

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: 
        return render_template('login.html', error='Username does not exist')

    # Verify password
    try:
        ph = PasswordHasher()
        ph.verify(account[1], password)
    except VerifyMismatchError:
        return render_template('login.html', error='Incorrect password')

    # Check if password hash needs to be updated
    if ph.check_needs_rehash(account[1]):
        query = 'update set password = :password where username = :username'
        params = {'password': ph.hash(password), 'username': account[0]}

        with contextlib.closing(sqlite3.connect(database)) as conn:
            with conn:
                conn.execute(query, params)

    # Set cookie for user session
    set_session(
        username=account[0], 
        email=account[2], 
        remember_me='remember-me' in request.form
    )
    
    return redirect('/predict1')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Store data to variables 
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    username = request.form.get('username')
    email = request.form.get('email')

    # Verify data
    if len(password) < 8:
        return render_template('register.html', error='Your password must be 8 or more characters')
    if password != confirm_password:
        return render_template('register.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register.html', error='Username must only be letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register.html', error='Username must be between 4 and 25 characters')

    query = 'select username from users where username = :username;'
    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register.html', error='Username already exists')

    # Create password hash
    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    query = 'insert into users(username, password, email) values (:username, :password, :email);'
    params = {
        'username': username,
        'password': hashed_password,
        'email': email
    }

    with contextlib.closing(sqlite3.connect(database)) as conn:
        with conn:
            result = conn.execute(query, params)

    # We can log the user in right away since no email verification
    set_session( username=username, email=email)
    return redirect('/')


@app.route('/predict1')
def index():
    return render_template('index.html')


@app.route('/uploade', methods=['POST', 'GET'])
def upload_file():
    if request.method == 'POST':
        # f.save("somefile.jpeg")
        # f = request.files['file']

        f = request.files['file'].read()
        npimg = np.fromstring(f, np.uint8)
        img = cv2.imdecode(npimg, cv2.IMREAD_GRAYSCALE)
        face_properties = classifier.classify(img, face_detector, model)

        return json.dumps(face_properties)


if __name__ == '__main__':

    # Run the flask app
    app.run()