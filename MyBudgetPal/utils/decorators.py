from functools import wraps
from flask import session, redirect, url_for, flash

def login_required(f):
    @wraps(f)
    def check_login_function(*args, **kwargs):
        if not session.get("user_id") or not session.get("username"):
            flash("You must be logged in to access this page.", "warning")
            return redirect(url_for("auth.signin"))
        return f(*args, **kwargs)
    return check_login_function

def guest_only(f):
    @wraps(f)
    def check_guest(*args, **kwargs):
        if session.get("user_id"):
            return redirect(url_for("dashboard.index"))
        return f(*args, **kwargs)
    return check_guest