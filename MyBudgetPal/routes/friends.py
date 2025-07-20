from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, jsonify
from utils.decorators import login_required
from utils.helpers import get_db
from utils.helpers import get_db, get_logged_cursor
from utils.logging_config import setup_logger, get_user_context
import bleach
import logging
import os

friends_bp = Blueprint('friends', __name__)

# Set up logging
logger = setup_logger("friends")

@friends_bp.route("/friends")
@login_required
def friends():
    current_user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Friends page accessed by user '{username}' (ID: {current_user_id}) from IP {ip_address}")
    
    # Use logged cursor instead of regular cursor
    cursor = get_logged_cursor(dictionary=True)

    try:
        # Get friends of the current user
        cursor.execute(
            """
            SELECT u.user_id, u.username
            FROM users u
            JOIN friend f ON f.friend_id = u.user_id
            WHERE f.user_id = %s
        """,
            (current_user_id,),
        )
        friends = cursor.fetchall()

        # Get pending friend requests received by the current user
        cursor.execute(
            """
            SELECT u.user_id, u.username, fr.request_id
            FROM users u
            JOIN friend_requests fr ON (fr.receiver_id = %s AND fr.requester_id = u.user_id)
            WHERE fr.status = 'pending'
        """,
            (current_user_id,),
        )
        pending_requests = cursor.fetchall()
        
        logger.info(f"Friends data loaded for user '{username}' (ID: {current_user_id}): {len(friends)} friends, {len(pending_requests)} pending requests from IP {ip_address}")
        
    except Exception as e:
        logger.error(f"Error fetching friends for user '{username}' (ID: {current_user_id}): {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error fetching friends: {e}")
        flash("An error occurred while fetching friends.", "danger")
        friends = []
        pending_requests = []
    finally:
        cursor.close()
        
    return render_template(
        "friends.html", friends=friends, pending_requests=pending_requests
    )

@friends_bp.route("/send-friend-request", methods=["POST"])
@login_required
def send_friend_request():
    friend_username = bleach.clean(request.form.get("friend_username"))
    requester_id = session.get("user_id")
    requester_username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Friend request attempt by user '{requester_username}' (ID: {requester_id}) to user '{friend_username}' from IP {ip_address}")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT user_id FROM users WHERE username = %s", (friend_username,)
        )
        friend = cursor.fetchone()
        
        if not friend:
            logger.warning(f"Friend request failed - user not found: user '{requester_username}' (ID: {requester_id}) tried to send request to non-existent user '{friend_username}' from IP {ip_address}")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return "", 404
            flash("User not found.", "danger")
            return redirect(url_for("friends.friends"))
            
        friend_id = friend["user_id"]
        
        # Check if trying to add self
        if friend_id == requester_id:
            logger.warning(f"Friend request failed - self-request attempt: user '{requester_username}' (ID: {requester_id}) tried to send request to themselves from IP {ip_address}")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return "", 400
            flash("Cannot send friend request to yourself.", "danger")
            return redirect(url_for("friends.friends"))
        
        cursor.execute(
            """
            SELECT * FROM friend_requests
            WHERE requester_id = %s AND receiver_id = %s AND status = 'pending'
        """,
            (requester_id, friend_id),
        )
        
        if cursor.fetchone():
            logger.warning(f"Friend request failed - already pending: user '{requester_username}' (ID: {requester_id}) tried to send duplicate request to '{friend_username}' (ID: {friend_id}) from IP {ip_address}")
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return "", 409
            flash("Friend request already pending.", "warning")
            return redirect(url_for("friends.friends"))
            
        cursor.execute(
            """
            INSERT INTO friend_requests (requester_id, receiver_id, status, requested_at)
            VALUES (%s, %s, 'pending', NOW())
        """,
            (requester_id, friend_id),
        )
        
        # Commit with logging
        db = get_db()
        db.commit()
        
        logger.info(f"Friend request sent successfully by user '{requester_username}' (ID: {requester_id}) to '{friend_username}' (ID: {friend_id}) from IP {ip_address}")
        
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return "", 200
        flash("Friend request sent!", "success")
        
    except Exception as e:
        logger.error(f"Friend request failed for user '{requester_username}' (ID: {requester_id}) to '{friend_username}': {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error sending friend request: {e}")
        db = get_db()
        db.rollback()
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return "", 500
        flash("An error occurred.", "danger")
    finally:
        cursor.close()
        
    return redirect(url_for("friends.friends"))

@friends_bp.route("/api/search-username", methods=["GET"])
@login_required
def api_search_username():
    query = request.args.get("query", "").strip()
    current_user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Username search by user '{username}' (ID: {current_user_id}) for query '{query}' from IP {ip_address}")
    
    results = []
    if query:
        db = get_db()
        cursor = db.cursor(dictionary=True)
        try:
            # Find user by exact username (case-insensitive), not self
            cursor.execute(
                """
                SELECT user_id, username FROM users
                WHERE LOWER(username) = %s AND user_id != %s
                """,
                (query.lower(), current_user_id),
            )
            user = cursor.fetchone()
            if user:
                # Check if already friends
                cursor.execute(
                    """
                    SELECT 1 FROM friend
                    WHERE (user_id = %s AND friend_id = %s)
                       OR (user_id = %s AND friend_id = %s)
                    """,
                    (
                        current_user_id,
                        user["user_id"],
                        user["user_id"],
                        current_user_id,
                    ),
                )
                is_friend = cursor.fetchone() is not None

                # Check for pending friend request
                cursor.execute(
                    """
                    SELECT status FROM friend_requests
                    WHERE ((requester_id = %s AND receiver_id = %s)
                        OR (requester_id = %s AND receiver_id = %s))
                    ORDER BY requested_at DESC LIMIT 1
                    """,
                    (
                        current_user_id,
                        user["user_id"],
                        user["user_id"],
                        current_user_id,
                    ),
                )
                req = cursor.fetchone()
                status = req["status"] if req else None

                # Only show if not friend
                if not is_friend:
                    results.append(
                        {
                            "user_id": user["user_id"],
                            "username": user["username"],
                            "status": status,
                        }
                    )
                    logger.info(f"Username search result for user '{username}' (ID: {current_user_id}): found '{user['username']}' (ID: {user['user_id']}) with status '{status}' from IP {ip_address}")
                else:
                    logger.info(f"Username search result for user '{username}' (ID: {current_user_id}): found '{user['username']}' (ID: {user['user_id']}) but already friends from IP {ip_address}")
            else:
                logger.info(f"Username search result for user '{username}' (ID: {current_user_id}): no user found for query '{query}' from IP {ip_address}")
        except Exception as e:
            logger.error(f"Username search error for user '{username}' (ID: {current_user_id}) query '{query}': {str(e)} from IP {ip_address}")
            current_app.logger.error(f"Error searching for users: {e}")
        finally:
            cursor.close()
    return jsonify(results)


@friends_bp.route("/accept-friend-request", methods=["POST"])
@login_required
def accept_friend_request():
    request_id = bleach.clean(request.form.get("request_id"))
    current_user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Friend request acceptance attempt by user '{username}' (ID: {current_user_id}), Request ID: {request_id} from IP {ip_address}")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)
    try:
        # Get requester and receiver from the request
        cursor.execute(
            """
            SELECT requester_id, receiver_id FROM friend_requests
            WHERE request_id = %s AND status = 'pending'
        """,
            (request_id,),
        )
        req = cursor.fetchone()
        if req:
            requester_id = req["requester_id"]
            receiver_id = req["receiver_id"]
            
            # Verify the current user is the receiver
            if receiver_id != current_user_id:
                logger.warning(f"Unauthorized friend request acceptance attempt by user '{username}' (ID: {current_user_id}), Request ID: {request_id} - not the intended receiver from IP {ip_address}")
                flash("Unauthorized action.", "danger")
                return redirect(url_for("friends.friends"))
            
            # Update request status
            cursor.execute(
                """
                UPDATE friend_requests
                SET status = 'accepted', responded_at = NOW()
                WHERE request_id = %s
            """,
                (request_id,),
            )
            # Add to friends table (bidirectional)
            cursor.execute(
                """
                INSERT IGNORE INTO friend (user_id, friend_id) VALUES (%s, %s), (%s, %s)
            """,
                (requester_id, receiver_id, receiver_id, requester_id),
            )
            db.commit()
            
            logger.info(f"Friend request accepted successfully by user '{username}' (ID: {current_user_id}), Request ID: {request_id}, new friendship between users {requester_id} and {receiver_id} from IP {ip_address}")
            flash("Friend request accepted.", "success")
        else:
            logger.warning(f"Friend request acceptance failed - request not found: user '{username}' (ID: {current_user_id}), Request ID: {request_id} from IP {ip_address}")
            flash("Request not found or already handled.", "warning")
    except Exception as e:
        logger.error(f"Friend request acceptance failed for user '{username}' (ID: {current_user_id}), Request ID: {request_id}: {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error accepting friend request: {e}")
        flash("An error occurred.", "danger")
    finally:
        cursor.close()
    return redirect(url_for("friends.friends"))


@friends_bp.route("/decline-friend-request", methods=["POST"])
@login_required
def decline_friend_request():
    request_id = bleach.clean(request.form.get("request_id"))
    current_user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Friend request decline attempt by user '{username}' (ID: {current_user_id}), Request ID: {request_id} from IP {ip_address}")
    
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute(
            """
            UPDATE friend_requests
            SET status = 'declined', responded_at = NOW()
            WHERE request_id = %s AND status = 'pending' AND receiver_id = %s
        """,
            (request_id, current_user_id),
        )
        
        if cursor.rowcount > 0:
            db.commit()
            logger.info(f"Friend request declined successfully by user '{username}' (ID: {current_user_id}), Request ID: {request_id} from IP {ip_address}")
            flash("Friend request declined.", "info")
        else:
            logger.warning(f"Friend request decline failed - request not found or unauthorized: user '{username}' (ID: {current_user_id}), Request ID: {request_id} from IP {ip_address}")
            flash("Request not found or already handled.", "warning")
            
    except Exception as e:
        logger.error(f"Friend request decline failed for user '{username}' (ID: {current_user_id}), Request ID: {request_id}: {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error declining friend request: {e}")
        flash("An error occurred.", "danger")
    finally:
        cursor.close()
    return redirect(url_for("friends.friends"))


@friends_bp.route("/remove_friend", methods=["POST"])
@login_required
def remove_friend():
    friend_id = bleach.clean(request.form.get("friend_id"))
    user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Friend removal attempt by user '{username}' (ID: {user_id}), removing friend ID: {friend_id} from IP {ip_address}")
    
    db = get_db()
    cursor = db.cursor()
    try:
        # Remove both directions of friendship
        cursor.execute(
            """
            DELETE FROM friend
            WHERE (user_id = %s AND friend_id = %s)
               OR (user_id = %s AND friend_id = %s)
        """,
            (user_id, friend_id, friend_id, user_id),
        )
        
        if cursor.rowcount > 0:
            db.commit()
            logger.info(f"Friend removed successfully by user '{username}' (ID: {user_id}), removed friend ID: {friend_id}, {cursor.rowcount} rows affected from IP {ip_address}")
            flash("Friend removed.", "success")
        else:
            logger.warning(f"Friend removal failed - no friendship found: user '{username}' (ID: {user_id}), friend ID: {friend_id} from IP {ip_address}")
            flash("Friend not found or already removed.", "warning")
            
    except Exception as e:
        logger.error(f"Friend removal failed for user '{username}' (ID: {user_id}), friend ID: {friend_id}: {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error removing friend: {e}")
        flash("An error occurred.", "danger")
    finally:
        cursor.close()
    return redirect(url_for("friends.friends"))