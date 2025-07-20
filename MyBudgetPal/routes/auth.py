import re
import datetime
import secrets
import hashlib
import requests
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from utils.decorators import login_required, guest_only
from utils.helpers import get_db, get_logged_cursor, load_common_passwords
from utils.session_tracker import track_activity, track_session_activity
from utils.logging_config import setup_logger, get_user_context
from extensions import bcrypt
import bleach
import logging
import os
import pyotp
import qrcode
import io
import base64

auth_bp = Blueprint('auth', __name__)
COMMON_PASSWORDS = load_common_passwords()

# Setup logging
logger = setup_logger("auth")

@auth_bp.route("/locked")
def locked():  # Removed @login_required since banned users can't login
    ip_address = request.remote_addr
    logger.info(f"Locked page accessed from IP {ip_address}")
    return render_template("locked.html", show_reset_link=True)

@auth_bp.route("/reset", methods=["GET", "POST"])
@guest_only
def reset():
    if request.method == "POST":
        ip_address = request.remote_addr
        email = request.form.get("email")

        logger.info(
            f"Password reset request for email '{email}' from IP {ip_address}")

        if not email:
            flash("Email is required.", "danger")
            return render_template("reset.html")

        cursor = get_logged_cursor(dictionary=True)

        try:
            # Check if user exists
            cursor.execute(
                "SELECT user_id, username, email FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if not user:
                logger.warning(
                    f"Password reset attempted for non-existent email '{email}' from IP {ip_address}")
                # Don't reveal if email exists - show success message anyway for security
                flash(
                    "If this email exists in our system, you will receive a password reset link shortly.", "info")
                return render_template("reset.html")

            # Check rate limiting
            cursor.execute(
                "SELECT last_reset_request FROM users WHERE email = %s",
                (email,)
            )
            user_reset_data = cursor.fetchone()

            if user_reset_data and user_reset_data.get('last_reset_request'):
                time_since_last = datetime.datetime.now(datetime.timezone.utc) - user_reset_data['last_reset_request']
                if time_since_last < datetime.timedelta(minutes=5): 
                    logger.warning(f"Rate limited password reset request for email '{email}' from IP {ip_address}")
                    flash("Please wait before requesting another password reset.", "warning")
                    return render_template("reset.html")

            # Generate secure reset token
            reset_token = secrets.token_urlsafe(32)

            # Hash the token before storing in database
            token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
            reset_token_expires = datetime.datetime.now(
                datetime.timezone.utc) + datetime.timedelta(minutes=15)

            # Update last reset request time AND store HASHED token in database
            cursor.execute(
                """
                UPDATE users 
                SET last_reset_request = %s, reset_token_hash = %s, reset_token_expires = %s 
                WHERE user_id = %s
                """,
                (datetime.datetime.now(datetime.timezone.utc),
                 token_hash, reset_token_expires, user["user_id"])
            )

            # COMMIT THE TRANSACTION - THIS WAS MISSING!
            db = get_db()
            db.commit()

            # Debug logging
            logger.info(
                f"Reset token stored in database for user '{user['username']}' - Token hash: {token_hash[:10]}...")

            # Send the plain token in email (never store this)
            reset_link = url_for('auth.reset_password',
                                 token=reset_token, _external=True)

            if send_reset_email(user["email"], user["username"], reset_link):
                logger.info(
                    f"Password reset email sent successfully to '{email}' for user '{user['username']}' from IP {ip_address}")
                flash(
                    "If this email exists in our system, you will receive a password reset link shortly.", "info")
            else:
                logger.error(
                    f"Failed to send password reset email to '{email}' for user '{user['username']}' from IP {ip_address}")
                flash(
                    "An error occurred while sending the reset email. Please try again later.", "danger")

        except Exception as e:
            db = get_db()
            db.rollback()
            logger.error(
                f"Password reset error for email '{email}' from IP {ip_address}: {e}")
            flash("An error occurred. Please try again later.", "danger")
        finally:
            cursor.close()

    return render_template("reset.html")


def send_reset_email(email, username, reset_link):
    """Send password reset email using Mailgun"""
    try:
        # Mailgun configuration
        mailgun_api_key = current_app.config.get(
            'MAILGUN_API_KEY') or os.getenv('MAILGUN_API_KEY')
        mailgun_domain = current_app.config.get('MAILGUN_DOMAIN') or os.getenv(
            'MAILGUN_DOMAIN', 'mail.bobbylab.com')
        from_email = f"MyBudgetPal <noreply@mybudgetpal.com>"

        if not mailgun_api_key:
            logger.error("Mailgun API key not configured")
            return False

        # HTML email template
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Password Reset - MyBudgetPal</title>
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background-color: #f8f9fa; padding: 30px; border-radius: 10px;">
                <h2 style="color: #007bff; text-align: center;">MyBudgetPal</h2>
                <h3 style="color: #333;">Password Reset Request</h3>
                
                <p>Hello {username},</p>
                
                <p>We received a request to reset your password for your MyBudgetPal account. If you didn't make this request, you can safely ignore this email.</p>
                
                <p>To reset your password, click the button below:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_link}" 
                       style="background-color: #007bff; color: white; padding: 12px 30px; 
                              text-decoration: none; border-radius: 5px; display: inline-block;
                              font-weight: bold; border: none;">Reset My Password</a>
                </div>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style="background-color: #e9ecef; padding: 10px; border-radius: 5px; word-break: break-all; font-family: monospace;">
                    {reset_link}
                </p>
                
                <p><strong>Important:</strong> This link will expire in 15 minutes for security reasons.</p>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #dee2e6;">
                
                <p style="font-size: 12px; color: #6c757d;">
                    If you're having trouble clicking the button, copy and paste the URL above into your web browser.
                    <br><br>
                    This is an automated message from MyBudgetPal. Please do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """

        # Plain text version
        text_body = f"""
        MyBudgetPal - Password Reset Request
        
        Hello {username},
        
        We received a request to reset your password for your MyBudgetPal account.
        
        To reset your password, visit this link:
        {reset_link}
        
        This link will expire in 15 minutes for security reasons.
        
        If you didn't request this reset, you can safely ignore this email.
        
        Best regards,
        MyBudgetPal Team
        
        ---
        This is an automated message from MyBudgetPal. Please do not reply to this email.
        """

        # Debug logging to verify the link
        logger.info(f"Password reset link being sent: {reset_link}")

        # Send email via Mailgun
        response = requests.post(
            f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
            auth=("api", mailgun_api_key),
            data={
                "from": from_email,
                "to": f"{username} <{email}>",
                "subject": "MyBudgetPal - Password Reset Request",
                "text": text_body,
                "html": html_body,
                "o:tag": ["password-reset", "authentication"],
                "o:tracking": "no",
                "o:tracking-clicks": "no",
                "o:tracking-opens": "no"
            }
        )

        if response.status_code == 200:
            logger.info(
                f"Password reset email sent successfully via Mailgun to {email} for user {username}")
            return True
        else:
            logger.error(
                f"Failed to send password reset email via Mailgun to {email}. Status: {response.status_code}, Response: {response.text}")
            return False

    except Exception as e:
        logger.error(f"Failed to send reset email to {email} via Mailgun: {e}")
        return False


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@guest_only
def reset_password(token):
    ip_address = request.remote_addr

    cursor = get_logged_cursor(dictionary=True)

    try:
        # Hash the received token to compare with database
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Verify token and check if it's not expired
        cursor.execute(
            """
            SELECT user_id, username, email, reset_token_expires 
            FROM users 
            WHERE reset_token_hash = %s AND reset_token_expires > %s
            """,
            (token_hash, datetime.datetime.now(datetime.timezone.utc))
        )
        user = cursor.fetchone()

        if not user:
            logger.warning(
                f"Invalid or expired password reset token accessed from IP {ip_address}")
            flash(
                "Invalid or expired reset link. Please request a new password reset.", "danger")
            return redirect(url_for("auth.reset"))

        if request.method == "POST":
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")

            logger.info(
                f"Password reset submission for user '{user['username']}' from IP {ip_address}")

            # Validate password
            if not password or not confirm_password:
                flash("Both password fields are required.", "danger")
                return render_template("reset-password.html", token=token)

            if password != confirm_password:
                logger.warning(
                    f"Password mismatch during reset for user '{user['username']}' from IP {ip_address}")
                flash("Passwords do not match.", "danger")
                return render_template("reset-password.html", token=token)

            # Check password strength
            if (
                len(password) < 8
                or not re.search(r"[A-Z]", password)
                or not re.search(r"[a-z]", password)
                or not re.search(r"\d", password)
                or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
            ):
                logger.warning(
                    f"Weak password provided during reset for user '{user['username']}' from IP {ip_address}")
                flash(
                    "Password must be at least 8 characters with upper, lower, number, and special character.",
                    "danger",
                )
                return render_template("reset-password.html", token=token)

            if password in COMMON_PASSWORDS:
                flash(
                    "Password is too common. Please choose a more secure one!", "danger")
                return render_template("reset-password.html", token=token)

            # Hash new password
            hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

            # Update password and clear reset token, unban account
            cursor.execute(
                """
                UPDATE users 
                SET password_hash = %s, 
                    reset_token_hash = NULL, 
                    reset_token_expires = NULL,
                    failed_login_attempts = 0,
                    last_failed_attempt = NULL,
                    is_banned = FALSE,
                    banned_at = NULL
                WHERE user_id = %s
                """,
                (hashed_pw, user["user_id"])
            )

            db = get_db()
            db.commit()
            
            logger.info(f"Password reset successful for user '{user['username']}' from IP {ip_address}. Account unbanned.")
            flash("Password reset successful! You can now sign in with your new password.", "success")
            return redirect(url_for("auth.signin"))

    except Exception as e:
        db = get_db()
        db.rollback()
        logger.error(
            f"Password reset error for token from IP {ip_address}: {e}")
        flash("An error occurred. Please try again later.", "danger")
        return redirect(url_for("auth.reset"))
    finally:
        cursor.close()

    return render_template("reset-password.html", token=token)


@auth_bp.route("/account-reset-password", methods=["GET", "POST"])
@login_required
def logged_in_reset_password():
    user_id = session.get("user_id")  # or however you store logged-in info
    ip_address = request.remote_addr
    cursor = get_logged_cursor(dictionary=True)

    try:
        # Fetch current user data
        cursor.execute("SELECT password_hash, username FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("dashboard.index"))

        if request.method == "POST":
            current_password = request.form.get("current_password")
            new_password = request.form.get("new_password")
            confirm_password = request.form.get("confirm_password")
            
            logger.info(f"Password change attempt for user '{user['username']}' from IP {ip_address}")

            # Check current password
            if not bcrypt.check_password_hash(user["password_hash"], current_password):
                flash("Current password is incorrect.", "danger")
                return render_template("account-reset-password.html")

            # Match check
            if new_password != confirm_password:
                flash("New passwords do not match.", "danger")
                return render_template("account-reset-password.html")

            # Strength check
            if (
                len(new_password) < 8
                or not re.search(r"[A-Z]", new_password)
                or not re.search(r"[a-z]", new_password)
                or not re.search(r"\d", new_password)
                or not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password)
            ):
                flash(
                    "Password must be at least 8 characters with upper, lower, number, and special character.",
                    "danger"
                )
                return render_template("account-reset-password.html")
            
            if new_password in COMMON_PASSWORDS:
                flash("Password is too common. Please choose a more secure one!", "danger")
                return render_template("account-reset-password.html")

            # All good — update password
            hashed_pw = bcrypt.generate_password_hash(new_password).decode("utf-8")
            cursor.execute("UPDATE users SET password_hash = %s WHERE user_id = %s", (hashed_pw, user_id))
            
            db = get_db()
            db.commit()

            logger.info(f"Password updated for user '{user['username']}' from IP {ip_address}")
            flash("Your password has been updated successfully.", "success")
            return render_template("account-reset-password.html")

    except Exception as e:
        db = get_db()
        db.rollback()
        logger.error(f"Password update error for user {user_id} from IP {ip_address}: {e}")
        flash("An error occurred while updating your password.", "danger")
    finally:
        cursor.close()
    
    return render_template("account-reset-password.html")



@auth_bp.route("/signin", methods=["GET", "POST"])
@guest_only
def signin():
    if request.method == "POST":
        ip_address = request.remote_addr
        username = bleach.clean(request.form.get("username"))
        password = bleach.clean(request.form.get("password"))
        recaptcha_token = bleach.clean(
            request.form.get("g-recaptcha-response"))

         # Step 1: Verify reCAPTCHA v3 token with Google

        if not recaptcha_token:
            flash("CAPTCHA failed.", "danger")
            return redirect(url_for("auth.signin"))

        recaptcha_secret = current_app.config.get("RECAPTCHA_SECRET_KEY")
        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        payload = {
            "secret": recaptcha_secret,
            "response": recaptcha_token
        }

        try:
            r = requests.post(verify_url, data=payload)
            result = r.json()
            current_app.logger.debug(
                f"reCAPTCHA verification result: {result}")

            if not result.get("success"):
                flash("CAPTCHA failed.", "danger")
                return redirect(url_for("auth.signin"))

            if result.get("score", 0) < 0.5:
                flash("CAPTCHA failed.", "danger")
                return redirect(url_for("auth.signin"))

        except Exception as e:
            current_app.logger.error(f"reCAPTCHA error: {e}")
            flash("reCAPTCHA verification error. Try again later.", "danger")
            return redirect(url_for("auth.signin"))

        # Step 2: Database login with banning logic
        cursor = get_logged_cursor(dictionary=True)

        try:
            # First check if user exists
            cursor.execute(
                "SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()

            if not user:
                logger.warning(
                    f"Login attempt for non-existent user '{username}' from IP {ip_address}")
                flash("Invalid email or password.", "danger")
                return render_template("signin.html", site_key=current_app.config.get("RECAPTCHA_SITE_KEY"))

            # Check if email is verified
            if not user.get("email_verified"):
                logger.warning(
                    f"Login attempt for unverified email by user '{username}' from IP {ip_address}")
                flash(
                    "Please verify your email address before signing in. Check your inbox for the verification link.", "warning")
                return render_template("signin.html",
                                       show_resend_verification=True,
                                       user_email=user.get("email"),
                                       site_key=current_app.config.get("RECAPTCHA_SITE_KEY"))

            # Check if account is banned
            if user.get("is_banned"):
                logger.warning(f"Login attempt on banned account '{username}' from IP {ip_address}")
                flash("Your account has been banned due to multiple failed login attempts. Please reset your password to unlock your account.", "danger")
                return render_template("signin.html", show_reset_link=True, site_key=current_app.config.get("RECAPTCHA_SITE_KEY"))
            
            # Check password
            if bcrypt.check_password_hash(user["password_hash"], password):

                # Successful login - reset failed attempts if any
                if user.get("failed_login_attempts", 0) > 0:
                    cursor.execute(
                        """
                        UPDATE users 
                        SET failed_login_attempts = 0, last_failed_attempt = NULL
                        WHERE user_id = %s
                        """,
                        (user["user_id"],),
                    )
                    logger.info(
                        f"Failed login attempts reset for user '{username}' after successful login from IP {ip_address}")

                # Check if TOTP is enabled
                if user.get("is_totp_enabled"):
                    session.clear()
                    session["pending_2fa_user_id"] = user["user_id"]
                    session["pending_2fa_username"] = user["username"]
                    session["pending_2fa_email"] = user["email"]
                    flash(
                        "Two-Factor Authentication required. Please enter your code.", "info")
                    return redirect(url_for("auth.verify_2fa"))

                # Clear any existing session data and set new session
                session.clear()
                session["user_id"] = user["user_id"]
                session["username"] = user["username"]
                session["email"] = user["email"]
                session["is_active"] = True

                # Log session in the database (from your existing session tracking)
                try:
                    # Generate a secure session token
                    session_token = secrets.token_urlsafe(32)
                    hashed_token = hashlib.sha256(
                        session_token.encode()).hexdigest()

                    # Store the plain token in Flask session for validation
                    session["session_token"] = session_token

                    timeout_minutes = 15
                    now = datetime.datetime.now(datetime.timezone.utc)
                    expires_at = now + \
                        datetime.timedelta(minutes=timeout_minutes)

                    cursor.execute(
                        "INSERT INTO session (session_timestamp, hashed_token, user_id, ip_address, is_active, last_activity_at, expires_at) VALUES (%s, %s, %s, %s, TRUE, %s, %s)",
                        (now, hashed_token, user['user_id'],
                         request.remote_addr, now, expires_at)
                    )
                    # Get the session ID that was just created
                    session_id = cursor.lastrowid
                    session["db_session_id"] = session_id

                except Exception as e:
                    current_app.logger.error(f"Session logging error: {e}")
                    # Don't fail login if session logging fails

                # Update last login time and session_active status
                cursor.execute(
                    "UPDATE users SET last_login_at = %s, session_active = TRUE WHERE user_id = %s",
                    (datetime.datetime.now(
                        datetime.timezone.utc), user["user_id"]),
                )

                # Commit the transaction
                db = get_db()
                db.commit()

                # Log successful login
                logger.info(f"User '{username}' logged in successfully from IP {ip_address}")

                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for("dashboard.index"))

            else:
                # Failed login - increment counter and check for ban
                new_failed_attempts = user.get("failed_login_attempts", 0) + 1

                # Configuration constant
                MAX_FAILED_ATTEMPTS = 5

                if new_failed_attempts >= MAX_FAILED_ATTEMPTS:
                    # Ban the account
                    cursor.execute(
                        """
                        UPDATE users 
                        SET failed_login_attempts = %s, last_failed_attempt = %s,
                            is_banned = TRUE, banned_at = %s
                        WHERE user_id = %s
                        """,
                        (new_failed_attempts, datetime.datetime.now(datetime.timezone.utc),
                         datetime.datetime.now(datetime.timezone.utc), user["user_id"]),
                    )

                    logger.warning(
                        f"Account '{username}' BANNED after {new_failed_attempts} failed attempts from IP {ip_address}")
                    flash(
                        f"Account banned due to multiple failed login attempts. Please reset your password to unlock your account.", "danger")

                    db = get_db()
                    db.commit()
                    return render_template("signin.html", show_reset_link=True, site_key=current_app.config.get("RECAPTCHA_SITE_KEY"))

                else:
                    # Update failed attempts count
                    cursor.execute(
                        """
                        UPDATE users 
                        SET failed_login_attempts = %s, last_failed_attempt = %s
                        WHERE user_id = %s
                        """,
                        (new_failed_attempts, datetime.datetime.now(
                            datetime.timezone.utc), user["user_id"]),
                    )

                    remaining_attempts = MAX_FAILED_ATTEMPTS - new_failed_attempts

                    logger.warning(
                        f"Failed login attempt #{new_failed_attempts} for user '{username}' from IP {ip_address}. {remaining_attempts} attempts remaining")
                    flash(f"Invalid email or password.", "warning")

                db = get_db()
                db.commit()

        except Exception as e:
            logger.error(
                f"Login error for username '{username}' from IP {ip_address}: {e}")
            current_app.logger.error(f"Login error: {e}")
            flash("An error occurred during login.", "danger")

        finally:
            cursor.close()

    return render_template("signin.html", site_key=current_app.config.get("RECAPTCHA_SITE_KEY"))


@auth_bp.route("/signup", methods=["GET", "POST"])
@guest_only
def signup():
    if request.method == "POST":
        ip_address = request.remote_addr
        username = bleach.clean(request.form.get("username"))
        email = bleach.clean(request.form.get("email"))
        password = bleach.clean(request.form.get("password"))
        confirm_password = bleach.clean(request.form.get("confirm_password"))
        recaptcha_token = bleach.clean(
            request.form.get("g-recaptcha-response"))

        # Log signup attempt
        logger.info(
            f"Signup attempt for username '{username}', email '{email}' from IP {ip_address}")

        # Step 1: Verify reCAPTCHA token
        verify_url = "https://www.google.com/recaptcha/api/siteverify"
        payload = {
            "secret": current_app.config.get("RECAPTCHA_SECRET_KEY"),
            "response": recaptcha_token
        }

        try:
            r = requests.post(verify_url, data=payload)
            result = r.json()
            current_app.logger.debug(f"reCAPTCHA (signup) result: {result}")

            if not result.get("success") or result.get("score", 0) < 0.5:
                logger.warning(f"reCAPTCHA failed for signup attempt from IP {ip_address}")
                flash("CAPTCHA failed. Please try again.", "danger")
                return redirect(url_for("auth.signup"))

        except Exception as e:
            current_app.logger.error(f"reCAPTCHA error on signup: {e}")
            flash("Verification error. Please try again later.", "danger")
            return redirect(url_for("auth.signup"))

        # Step 2: Basic validations
        if not email or not password or not username:
            logger.warning(
                f"Signup failed - missing fields for username '{username}' from IP {ip_address}")
            flash("All fields are required.", "danger")
            return redirect(url_for("auth.signup"))

        if (
            len(password) < 8
            or not re.search(r"[A-Z]", password)
            or not re.search(r"[a-z]", password)
            or not re.search(r"\d", password)
            or not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)
        ):
            logger.warning(
                f"Signup failed - weak password for username '{username}' from IP {ip_address}")
            flash(
                "Password must be at least 8 characters with upper, lower, number, and special character.",
                "danger",
            )
            return redirect(url_for("auth.signup"))

        if password in COMMON_PASSWORDS:
            flash("Password is too common. Please choose a more secure one.",
                   "danger")
            return redirect(url_for("auth.signup"))

        # Check if passwords match
        if password != confirm_password:
            logger.warning(
                f"Signup failed - password mismatch for username '{username}' from IP {ip_address}")
            flash("Passwords do not match.", "danger")
            return redirect(url_for("auth.signup"))

        # Use logged cursor instead of regular cursor
        cursor = get_logged_cursor()

        try:
            # Check for existing user
            cursor.execute(
                "SELECT * FROM users WHERE email = %s OR username = %s", (
                    email, username)
            )
            if cursor.fetchone():
                logger.warning(
                    f"Signup failed - duplicate email/username '{username}'/'{email}' from IP {ip_address}")
                flash("Email or username already exists.", "danger")
                return redirect(url_for("auth.signup"))

            # Generate email verification token
            verification_token = secrets.token_urlsafe(32)
            verification_expires = datetime.datetime.now(
                datetime.timezone.utc) + datetime.timedelta(hours=24)  # 24 hour expiry

            hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
            # Insert user with email verification token (email_verified = FALSE by default)
            cursor.execute(
                """
                INSERT INTO users (username, email, password_hash, email_verified, 
                                 email_verification_token, email_verification_token_expires) 
                VALUES (%s, %s, %s, FALSE, %s, %s)
                """,
                (username, email, hashed_pw,
                 verification_token, verification_expires),
            )

            # Get the user ID for logging
            user_id = cursor.lastrowid

            # Commit the transaction
            db = get_db()
            db.commit()

            # Send verification email
            verification_link = url_for(
                'auth.verify_email_token', token=verification_token, _external=True)

            if send_verification_email(email, username, verification_link):
                logger.info(
                    f"User '{username}' registered successfully from IP {ip_address}. Verification email sent.")
                flash("Registration successful! Please check your email and click the verification link before signing in.", "success")
                return redirect(url_for("auth.signin"))
            else:
                logger.error(
                    f"Failed to send verification email to '{email}' for user '{username}' from IP {ip_address}")
                flash(
                    "Registration successful, but we couldn't send the verification email. Please contact support.", "warning")
                return redirect(url_for("auth.signin"))

        except Exception as e:
            db = get_db()
            db.rollback()  # Rollback on error
            current_app.logger.error(f"Signup error: {e}")
            logger.error(
                f"Signup error for username '{username}' from IP {ip_address}: {e}")
            flash("Internal error. Try again later.", "danger")
        finally:
            cursor.close()

    return render_template("signup.html", site_key=current_app.config.get("RECAPTCHA_SITE_KEY"))


def send_verification_email(email, username, verification_link):
    """Send email verification email using Mailgun"""
    try:
        # Mailgun configuration
        mailgun_api_key = current_app.config.get(
            'MAILGUN_API_KEY') or os.getenv('MAILGUN_API_KEY')
        mailgun_domain = current_app.config.get('MAILGUN_DOMAIN') or os.getenv(
            'MAILGUN_DOMAIN', 'mail.bobbylab.com')
        # Use your actual domain
        from_email = f"MyBudgetPal <noreply@{mailgun_domain}>"

        if not mailgun_api_key:
            logger.error("Mailgun API key not configured")
            return False

        # HTML email template
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Email Verification - MyBudgetPal</title>
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background-color: #f8f9fa; padding: 30px; border-radius: 10px;">
                <h2 style="color: #007bff; text-align: center;">Welcome to MyBudgetPal!</h2>
                <h3 style="color: #333;">Please Verify Your Email Address</h3>
                
                <p>Hello {username},</p>
                
                <p>Thank you for signing up for MyBudgetPal! To complete your registration and start using your account, please verify your email address.</p>
                
                <p>Click the button below to verify your email:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_link}" 
                       style="background-color: #28a745; color: white; padding: 12px 30px; 
                              text-decoration: none; border-radius: 5px; display: inline-block;
                              font-weight: bold; border: none;">Verify My Email</a>
                </div>
                
                <p>Or copy and paste this link into your browser:</p>
                <p style="background-color: #e9ecef; padding: 10px; border-radius: 5px; word-break: break-all; font-family: monospace;">
                    {verification_link}
                </p>
                
                <p><strong>Important:</strong> This verification link will expire in 24 hours.</p>
                
                <p>Once you verify your email, you'll be able to sign in and start managing your budget with MyBudgetPal!</p>
                
                <hr style="margin: 30px 0; border: none; border-top: 1px solid #dee2e6;">
                
                <p style="font-size: 12px; color: #6c757d;">
                    If you didn't create an account with MyBudgetPal, you can safely ignore this email.
                    <br><br>
                    This is an automated message from MyBudgetPal. Please do not reply to this email.
                </p>
            </div>
        </body>
        </html>
        """

        # Plain text version
        text_body = f"""
        Welcome to MyBudgetPal - Email Verification Required
        
        Hello {username},
        
        Thank you for signing up for MyBudgetPal! To complete your registration, please verify your email address.
        
        Click this link to verify your email:
        {verification_link}
        
        This verification link will expire in 24 hours.
        
        Once verified, you'll be able to sign in and start managing your budget!
        
        If you didn't create this account, you can safely ignore this email.
        
        Best regards,
        MyBudgetPal Team
        
        ---
        This is an automated message from MyBudgetPal. Please do not reply to this email.
        """

        # Send email via Mailgun - DISABLE TRACKING
        response = requests.post(
            f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
            auth=("api", mailgun_api_key),
            data={
                "from": from_email,
                "to": f"{username} <{email}>",
                "subject": "MyBudgetPal - Please Verify Your Email Address",
                "text": text_body,
                "html": html_body,
                "o:tag": ["email-verification", "registration"],
                "o:tracking": "no",
                "o:tracking-clicks": "no",
                "o:tracking-opens": "no"
            }
        )

        if response.status_code == 200:
            logger.info(
                f"Email verification sent successfully via Mailgun to {email} for user {username}")
            return True
        else:
            logger.error(
                f"Failed to send verification email via Mailgun to {email}. Status: {response.status_code}, Response: {response.text}")
            return False

    except Exception as e:
        logger.error(
            f"Failed to send verification email to {email} via Mailgun: {e}")
        return False


@auth_bp.route("/verify-email/<token>")
@guest_only
def verify_email_token(token):
    """Handle email verification when user clicks the link"""
    ip_address = request.remote_addr

    cursor = get_logged_cursor(dictionary=True)

    try:
        # Find user with this verification token
        cursor.execute(
            """
            SELECT user_id, username, email, email_verification_token_expires 
            FROM users 
            WHERE email_verification_token = %s AND email_verification_token_expires > %s
            """,
            (token, datetime.datetime.now(datetime.timezone.utc))
        )
        user = cursor.fetchone()

        if not user:
            logger.warning(
                f"Invalid or expired email verification token accessed from IP {ip_address}")
            flash("Invalid or expired verification link. Please sign up again or request a new verification email.", "danger")
            return redirect(url_for("auth.signup"))

        # Check if already verified
        cursor.execute(
            "SELECT email_verified FROM users WHERE user_id = %s", (user["user_id"],))
        user_status = cursor.fetchone()

        if user_status and user_status.get("email_verified"):
            logger.info(
                f"Already verified email verification attempted for user '{user['username']}' from IP {ip_address}")
            flash("Your email is already verified. You can sign in now.", "info")
            return redirect(url_for("auth.signin"))

        # Verify the email
        cursor.execute(
            """
            UPDATE users 
            SET email_verified = TRUE, 
                email_verification_token = NULL, 
                email_verification_token_expires = NULL
            WHERE user_id = %s
            """,
            (user["user_id"],)
        )

        db = get_db()
        db.commit()

        logger.info(
            f"Email verified successfully for user '{user['username']}' from IP {ip_address}")
        flash(
            "Email verified successfully! You can now sign in to your account. You may activate 2FA under settings once you have logged into your account.", "success")
        return redirect(url_for("auth.signin"))

    except Exception as e:
        db = get_db()
        db.rollback()
        logger.error(
            f"Email verification error for token from IP {ip_address}: {e}")
        flash("An error occurred during verification. Please try again later.", "danger")
        return redirect(url_for("auth.signup"))
    finally:
        cursor.close()


@auth_bp.route("/resend-verification", methods=["POST"])
@guest_only
def resend_verification():
    """Resend email verification link"""
    ip_address = request.remote_addr
    email = request.form.get("email")

    if not email:
        flash("Email is required.", "danger")
        return redirect(url_for("auth.signin"))

    cursor = get_logged_cursor(dictionary=True)

    try:
        # Check if user exists and is not verified
        cursor.execute(
            "SELECT user_id, username, email, email_verified FROM users WHERE email = %s",
            (email,)
        )
        user = cursor.fetchone()

        if not user:
            # Don't reveal if email exists
            flash(
                "If this email exists and is unverified, a new verification link has been sent.", "info")
            return redirect(url_for("auth.signin"))

        if user.get("email_verified"):
            flash("This email is already verified. You can sign in now.", "info")
            return redirect(url_for("auth.signin"))

        # Generate new verification token
        verification_token = secrets.token_urlsafe(32)
        verification_expires = datetime.datetime.now(
            datetime.timezone.utc) + datetime.timedelta(hours=24)

        # Update the verification token
        cursor.execute(
            """
            UPDATE users 
            SET email_verification_token = %s, email_verification_token_expires = %s 
            WHERE user_id = %s
            """,
            (verification_token, verification_expires, user["user_id"])
        )

        db = get_db()
        db.commit()

        # Send new verification email
        verification_link = url_for(
            'auth.verify_email_token', token=verification_token, _external=True)

        if send_verification_email(user["email"], user["username"], verification_link):
            logger.info(
                f"Verification email resent to '{email}' from IP {ip_address}")
            flash("A new verification link has been sent to your email.", "success")
        else:
            logger.error(
                f"Failed to resend verification email to '{email}' from IP {ip_address}")
            flash("Failed to send verification email. Please try again later.", "danger")

    except Exception as e:
        db = get_db()
        db.rollback()
        logger.error(
            f"Resend verification error for email '{email}' from IP {ip_address}: {e}")
        flash("An error occurred. Please try again later.", "danger")
    finally:
        cursor.close()

    return redirect(url_for("auth.signin"))


@auth_bp.route("/logout")
def logout():
    ip_address = request.remote_addr
    user_id = session.get("user_id")
    username = session.get("username")

    # Update session_active status in the database
    db = get_db()
    if db:
        cursor = db.cursor()

        try:
            # Mark user as inactive
            cursor.execute(
                "UPDATE users SET session_active = FALSE WHERE user_id = %s",
                (user_id,),
            )

            # Mark database session as inactive
            if session.get("db_session_id"):
                cursor.execute(
                    "UPDATE session SET is_active = FALSE WHERE session_id = %s",
                    (session.get("db_session_id"),),
                )
            db.commit()

            # Log successful logout
            logger.info(
                f"User '{username}' (ID: {user_id}) logged out successfully from IP {ip_address}")

        except Exception as e:
            # Log database connection/update issue
            logger.warning(
                f"Database error during logout for user '{username}' (ID: {user_id}) from IP {ip_address}: {e}")
            current_app.logger.error(f"Logout database error: {e}")
        finally:
            cursor.close()

    # Clear session data
    session.clear()

    return redirect(url_for("auth.signin"))


@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user_id = session.get("user_id")
    username = session.get("username")

    cursor = get_logged_cursor(dictionary=True)

    cursor.execute(
        "SELECT is_totp_enabled FROM users WHERE user_id = %s", (user_id,))
    result = cursor.fetchone()

    if result.get("is_totp_enabled"):
        flash("2FA is already enabled. You must disable it before setting it up again.", "warning")
        return redirect(url_for("extras.settings"))

    db = get_db()

    if request.method == "POST":
        otp = request.form.get("otp")
        secret = session.get("temp_totp_secret")

        if not otp or not secret:
            flash("Missing OTP or secret.", "danger")
            return redirect(url_for("auth.setup_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(otp, valid_window=1):
            try:
                cursor.execute("""
                    UPDATE users 
                    SET totp_secret = %s, is_totp_enabled = TRUE
                    WHERE user_id = %s
                """, (secret, user_id))
                db.commit()
                flash("2FA setup successfully!", "success")
                session.pop("temp_totp_secret", None)
                return redirect(url_for("extras.settings"))
            except Exception as e:
                db.rollback()
                current_app.logger.error(
                    f"Error enabling 2FA for user {username}: {e}")
                flash("Internal error setting up 2FA.", "danger")
        else:
            flash("Invalid code. Please try again.", "danger")

    # Generate new secret and QR code
    secret = pyotp.random_base32()
    session["temp_totp_secret"] = secret
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="MyBudgetPal")

    # Generate QR code
    qr = qrcode.make(totp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')

    return render_template("setup_2fa.html", qr_code=img_base64, secret=secret)


@auth_bp.route("/disable-2fa", methods=["GET", "POST"])
@login_required
def disable_2fa():
    user_id = session.get("user_id")
    username = session.get("username")
    cursor = get_logged_cursor(dictionary=True)
    db = get_db()

    if request.method == "POST":
        password = request.form.get("password")

        cursor.execute(
            "SELECT password_hash FROM users WHERE user_id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("extras.settings"))

        if not bcrypt.check_password_hash(user["password_hash"], password):
            flash("Incorrect password.", "danger")
            return redirect(url_for("auth.disable_2fa"))

        try:
            cursor.execute("""
                UPDATE users 
                SET is_totp_enabled = FALSE, totp_secret = NULL
                WHERE user_id = %s
            """, (user_id,))
            db.commit()
            flash("2FA has been disabled successfully.", "success")
            return redirect(url_for("extras.settings"))
        except Exception as e:
            db.rollback()
            current_app.logger.error(
                f"Error disabling 2FA for user {username}: {e}")
            flash("Error disabling 2FA. Please try again.", "danger")
        finally:
            cursor.close()

    return render_template("disable_2fa.html")


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
@guest_only
def verify_2fa():
    if "user_id" in session:
        # User is already logged in
        return redirect(url_for("dashboard.index"))

    user_id = session.get("pending_2fa_user_id")
    username = session.get("pending_2fa_username")
    email = session.get("pending_2fa_email")

    if not user_id:
        flash("No pending login found.", "warning")
        return redirect(url_for("auth.signin"))

    cursor = get_logged_cursor(dictionary=True)
    db = get_db()

    try:
        cursor.execute(
            "SELECT totp_secret FROM users WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        if not result or not result.get("totp_secret"):
            flash("TOTP not configured for this account.", "danger")
            return redirect(url_for("auth.signin"))

        totp = pyotp.TOTP(result["totp_secret"])

        if request.method == "POST":
            otp_input = request.form.get("otp")
            if totp.verify(otp_input, valid_window=1):
                # OTP correct – perform full login now
                session.clear()
                session["user_id"] = user_id
                session["username"] = username
                session["email"] = email
                session["is_active"] = True

                session_token = secrets.token_urlsafe(32)
                hashed_token = hashlib.sha256(
                    session_token.encode()).hexdigest()
                now = datetime.datetime.now(datetime.timezone.utc)
                expires_at = now + datetime.timedelta(minutes=15)

                try:
                    cursor.execute(
                        "INSERT INTO session (session_timestamp, hashed_token, user_id, ip_address, is_active, last_activity_at, expires_at) VALUES (%s, %s, %s, %s, TRUE, %s, %s)",
                        (now, hashed_token, user_id,
                         request.remote_addr, now, expires_at)
                    )
                    session["session_token"] = session_token
                    session["db_session_id"] = cursor.lastrowid
                except Exception as e:
                    current_app.logger.error(
                        f"Session logging failed post-2FA: {e}")

                cursor.execute(
                    "UPDATE users SET last_login_at = %s, session_active = TRUE WHERE user_id = %s",
                    (now, user_id)
                )
                db.commit()

                flash("Login successful with 2FA.", "success")
                return redirect(url_for("dashboard.index"))
            else:
                flash("Invalid 2FA code. Please try again.", "danger")

    except Exception as e:
        db.rollback()
        current_app.logger.error(f"2FA login error: {e}")
        flash("Error during 2FA verification.", "danger")
    finally:
        cursor.close()

    return render_template("verify_2fa.html")
