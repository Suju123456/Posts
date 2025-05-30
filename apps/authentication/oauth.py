# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

import os
from flask import current_app as app 
from flask_login import current_user, login_user
from flask_dance.consumer import oauth_authorized
from flask_dance.contrib.github import github, make_github_blueprint
from flask_dance.contrib.google import google, make_google_blueprint
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from sqlalchemy.orm.exc import NoResultFound
from apps.config import Config
from apps.authentication.models import Users, db,OAuth
from flask import abort
from functools import wraps
from flask import flash, redirect,url_for, session
from functools import wraps
from flask import make_response

github_blueprint = make_github_blueprint(
    client_id=Config.GITHUB_ID,
    client_secret=Config.GITHUB_SECRET,
    scope = 'user',
    storage=SQLAlchemyStorage(
        OAuth,
        db.session,
        user=current_user,
        user_required=False,        
    ),   
)

@oauth_authorized.connect_via(github_blueprint)
def github_logged_in(blueprint, token):
    info = github.get("/user")

    if info.ok:

        account_info = info.json()
        username     = account_info["login"]

        query = Users.query.filter_by(oauth_github=username)
        try:

            user = query.one()
            login_user(user)

        except NoResultFound:

            # Save to db
            user              = Users()
            user.username     = '(gh)' + username
            user.oauth_github = username

            # Save current user
            db.session.add(user)
            db.session.commit()

            login_user(user)

# Google

google_blueprint = make_google_blueprint(
    client_id=Config.GOOGLE_ID,
    client_secret=Config.GOOGLE_SECRET,
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    ],
    storage=SQLAlchemyStorage(
        OAuth,
        db.session,
        user=current_user,
        user_required=False,        
    ),   
)

@oauth_authorized.connect_via(google_blueprint)
def google_logged_in(blueprint, token):
    info = google.get("/oauth2/v1/userinfo")

    if info.ok:
        account_info = info.json()
        username     = account_info["given_name"]
        email        = account_info["email"]

        query = Users.query.filter_by(oauth_google=username)
        try:

            user = query.one()
            login_user(user)

        except NoResultFound:
            # Save to db
            user              = Users()
            user.username     = '(google)' + username
            user.oauth_google = username
            user.email        = email

            # Save current user
            db.session.add(user)
            db.session.commit()

            login_user(user)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


def permission_required(permission_name):
    """Decorator to restrict access based on permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.has_permission(permission_name):
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response
    return no_cache