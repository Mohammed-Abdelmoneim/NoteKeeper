from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # looking in the database 
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("logged in successfully!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash("Incorrect password, try again.", category='fail')
        else:
            flash("Email does not exist.", category='fail')
            
        
        
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        full_name = request.form.get('fullName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        
        if user:
            flash("Email already exists!", category='fail')
        elif len(email) < 5:
            flash('Email must be more than 4 characters.', category='fail')
        elif len(full_name) < 2:
            flash('Full name must be more than 1 characters.', category='fail')
        elif password1 != password2:
            flash('Passwords don\'t match', category='fail')
        elif len(password1) < 5:
            flash('Password must be at least 5 characters.', category='fail')
        else:
            # go with this user
            new_user = User(email=email, full_name=full_name, password=generate_password_hash(password1, method='scrypt'))
            db.session.add(new_user)
            db.session.commit()
            flash('Acount created!', category='success')
            return redirect(url_for('views.home'))
    return render_template("sign_up.html", user=current_user)
