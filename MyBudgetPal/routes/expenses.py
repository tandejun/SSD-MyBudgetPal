from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from utils.decorators import login_required
from utils.helpers import get_db, load_categories, get_logged_cursor
from utils.logging_config import setup_logger, get_user_context
import datetime
import bleach
import logging
import os

expenses_bp = Blueprint('expenses', __name__)

# Set up logging
logger = setup_logger("expenses")

# Add Expense
@expenses_bp.route("/add-expense", methods=["GET", "POST"])
@login_required
def add_expense():
    # Get user_id for all methods
    userid = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    logger.info(f"Add expense page accessed by user '{username}' (ID: {userid}) from IP {ip_address}")

    # Load All Categories - Default, Custom
    userCategories = load_categories(userid)
    logger.info(f"Loaded {len(userCategories)} categories for user '{username}' (ID: {userid}) from IP {ip_address}")

    # Use logged cursor instead of regular cursor
    cursor = get_logged_cursor(dictionary=True)
    
    try:
        cursor.execute(
            """
            SELECT u.user_id, u.username
            FROM users u
            JOIN friend f ON f.friend_id = u.user_id
            WHERE f.user_id = %s
        """,
            (userid,),
        )
        friends = cursor.fetchall()
        logger.info(f"Loaded {len(friends)} friends for user '{username}' (ID: {userid}) from IP {ip_address}")

    except Exception as e:
        logger.error(f"Error loading friends for user '{username}' (ID: {userid}): {str(e)} from IP {ip_address}")
        friends = []
    finally:
        cursor.close()

    if request.method == "POST":

        paymethod = bleach.clean(request.form.get("method"))
        date = bleach.clean(request.form.get("date"))
        amount = bleach.clean(str(request.form.get("amount")))
        category = bleach.clean(request.form.get("category"))
        description = bleach.clean(request.form.get("description"))

        logger.info(f"Expense creation attempt by user '{username}' (ID: {userid}) from IP {ip_address}")
        
        share_with = [bleach.clean(fid) for fid in request.form.getlist("share_with[]") if fid]  # List of user_ids to share with

        # Log form data for security monitoring
        logger.info(f"Expense form data - User: '{username}' (ID: {userid}), Amount: '{amount}', Category: '{category}', Share with: {len(share_with)} friends, IP: {ip_address}")

        # Backend validation check for empty fields
        if not paymethod or not date or not amount or not category or not description:
            logger.warning(f"Expense creation failed - missing required fields for user '{username}' (ID: {userid}) from IP {ip_address}")
            error_message = "All fields are required!"
            return render_template("add-expense.html", error_message=error_message, categories=userCategories, friends=friends)

        # Validate and convert amount
        try:
            original_amount = amount
            amount = float(amount.replace("$", "").replace(",", ""))
            if amount < 0:
                logger.info(f"Invalid amount format for user '{username}' (ID: {userid}): '{original_amount}' -> {amount} from IP {ip_address}")
                error_message = "Invalid amount!"
                return render_template("add-expense.html", error_message=error_message, categories=userCategories, friends=friends)
            logger.info(f"Amount validation successful for user '{username}' (ID: {userid}): '{original_amount}' -> {amount} from IP {ip_address}")
        except ValueError:
            logger.warning(f"Invalid amount format for user '{username}' (ID: {userid}): '{amount}' from IP {ip_address}")
            error_message = "Invalid amount!"
            return render_template("add-expense.html", error_message=error_message, categories=userCategories, friends=friends)

        # Validate date input
        try:
            parsed_date = datetime.datetime.strptime(date, "%Y-%m-%d")
            if parsed_date.date() > datetime.datetime.now().date():
                raise ValueError("Expense Date cannot be in the future")
            logger.info(f"Date validation successful for user '{username}' (ID: {userid}): {date} from IP {ip_address}")
        except ValueError as e:
            logger.warning(f"Invalid date for user '{username}' (ID: {userid}): '{date}' - {str(e)} from IP {ip_address}")
            error_message = "Invalid Date! Please input a valid Date"
            return render_template("add-expense.html", error_message=error_message, categories=userCategories, friends=friends)

        # Use logged cursor for database operations
        cursor = get_logged_cursor(dictionary=True)
        
        try:
            if category == "custom":
                category = bleach.clean(request.form.get("custom_category"))
                logger.info(f"Custom category creation for user '{username}' (ID: {userid}): '{category}' from IP {ip_address}")

            category = category.strip().title()

            # Check if category exists in table
            cursor.execute(
                "SELECT category_id FROM categories WHERE LOWER(TRIM(category)) = LOWER(%s) AND (type = 'Default' or user_id = %s)",
                (category, userid),
            )
            category_exists = cursor.fetchone()

            # Insert new category defined by user
            if not category_exists:
                cursor.execute(
                    "INSERT INTO categories (category, user_id, type) VALUES (%s, %s, %s)",
                    (category, userid, "Custom"),
                )
                # Get the database connection for commit
                db = get_db()
                db.commit()
                category_id = cursor.lastrowid
                logger.info(f"New custom category created for user '{username}' (ID: {userid}): '{category}' (Category ID: {category_id}) from IP {ip_address}")
            else:
                category_id = category_exists["category_id"]
                logger.info(f"Using existing category for user '{username}' (ID: {userid}): '{category}' (Category ID: {category_id}) from IP {ip_address}")

            # Insert new Expense - SQL
            cursor.execute(
                "INSERT INTO expenses (user_id, amount, transaction_date, category_id, description, payment_method) VALUES (%s, %s, %s, %s, %s, %s)",
                (userid, amount, date, category_id, description, paymethod),
            )
            db = get_db()
            db.commit()
            expense_id = cursor.lastrowid
            logger.info(f"Expense created successfully for user '{username}' (ID: {userid}), Expense ID: {expense_id}, Amount: {amount} from IP {ip_address}")

            # Handle sharing with friends
            if share_with:
                logger.info(f"Processing expense sharing for user '{username}' (ID: {userid}), Expense ID: {expense_id}, sharing with {len(share_with)} friends from IP {ip_address}")
                try:
                    now = datetime.datetime.now()
                    shared_count = 0
                    for friend_id in share_with:
                        friend_id = int(friend_id)
                        cursor.execute(
                            """
                            INSERT INTO expense_requests (expense_id, from_user_id, to_user_id, amount, status, created_at, updated_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                expense_id,
                                userid,
                                friend_id,
                                amount,
                                "pending",
                                now,
                                now,
                            ),
                        )
                        shared_count += 1
                    db.commit()
                    logger.info(f"Expense sharing requests created successfully for user '{username}' (ID: {userid}), Expense ID: {expense_id}, {shared_count} requests created from IP {ip_address}")
                except Exception as e:
                    db.rollback()
                    logger.error(f"Failed to create expense sharing requests for user '{username}' (ID: {userid}), Expense ID: {expense_id}: {str(e)} from IP {ip_address}")
                    current_app.logger.error(f"Failed to create expense requests: {e}")
                    flash("Failed to create expense sharing requests.", "danger")

            flash("New Expense Added.", "success")
            return redirect(url_for("expenses.expense_add_succesful"))

        except Exception as e:
            db = get_db()
            db.rollback()
            logger.error(f"Expense creation failed for user '{username}' (ID: {userid}): {str(e)} from IP {ip_address}")
            current_app.logger.error(f"Failed to add expense: {e}")
            flash("Internal error. Try again.", "danger")
            
        finally:
            cursor.close()

    return render_template(
        "add-expense.html", categories=userCategories, friends=friends
    )

# Successful Expense Added
@expenses_bp.route("/expense-add-succesful")
@login_required
def expense_add_succesful():
    userid = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Expense success page accessed by user '{username}' (ID: {userid}) from IP {ip_address}")
    return render_template("expense-add-succesful.html")


# Approve Expense Request
@expenses_bp.route("/approve-expense-request", methods=["POST"])
@login_required
def approve_expense_request():
    request_id = bleach.clean(request.form.get("request_id"))
    user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Expense approval attempt by user '{username}' (ID: {user_id}), Request ID: {request_id} from IP {ip_address}")
    
    # Use logged cursor instead of regular cursor
    cursor = get_logged_cursor(dictionary=True)
    
    try:
        # Get the expense request details
        cursor.execute(
            """
            SELECT expense_id, amount
            FROM expense_requests
            WHERE request_id = %s AND to_user_id = %s AND status = 'pending'
        """,
            (request_id, user_id),
        )
        req = cursor.fetchone()
        if not req:
            logger.warning(f"Invalid expense approval attempt by user '{username}' (ID: {user_id}), Request ID: {request_id} - request not found or already handled from IP {ip_address}")
            flash("Request not found or already handled.", "warning")
            return redirect(url_for("dashboard.index"))

        expense_id = req["expense_id"]
        total_amount = req["amount"]
        logger.info(f"Processing expense approval for user '{username}' (ID: {user_id}), Expense ID: {expense_id}, Amount: {total_amount} from IP {ip_address}")

        # Get the original expense details
        cursor.execute(
            """
            SELECT transaction_date, category_id, description, payment_method
            FROM expenses
            WHERE expense_id = %s
        """,
            (expense_id,),
        )
        exp = cursor.fetchone()
        if not exp:
            logger.error(f"Original expense not found for user '{username}' (ID: {user_id}), Expense ID: {expense_id} from IP {ip_address}")
            flash("Original expense not found.", "danger")
            return redirect(url_for("dashboard.index"))

        # Get all related expense_ids for this expense
        cursor.execute(
            """
            SELECT expense_id FROM expenses
            WHERE split_from = %s
        """,
            (expense_id,),
        )
        related_expense_ids = [row["expense_id"] for row in cursor.fetchall()]
        split_count = len(related_expense_ids) + 2
        split_amount = float(total_amount) / split_count
        
        logger.info(f"Expense splitting calculation for user '{username}' (ID: {user_id}), Expense ID: {expense_id}: {split_count} participants, split amount: {split_amount} from IP {ip_address}")

        # Update the original expense to the new split amount
        cursor.execute(
            """
            UPDATE expenses SET amount = %s WHERE expense_id = %s
        """,
            (split_amount, expense_id),
        )

        # Update all previously approved users' expenses to the new split amount
        for related_expense_id in related_expense_ids:
            cursor.execute(
                """
                UPDATE expenses SET amount = %s
                WHERE expense_id = %s
            """,
                (split_amount, related_expense_id),
            )

        # Insert the expense for the approving user if not already present
        cursor.execute(
            """
            SELECT expense_id FROM expenses
            WHERE user_id = %s AND split_from = %s AND description = %s AND transaction_date = %s
            """,
            (user_id, expense_id, exp["description"], exp["transaction_date"])
        )
        if not cursor.fetchone():
            cursor.execute(
                """
                INSERT INTO expenses (user_id, amount, transaction_date, category_id, description, payment_method, split_from)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    user_id,
                    split_amount,
                    exp["transaction_date"],
                    exp["category_id"],
                    exp["description"],
                    exp["payment_method"],
                    expense_id,
                ),
            )
            logger.info(f"Split expense created for approving user '{username}' (ID: {user_id}), Original Expense ID: {expense_id}, Amount: {split_amount} from IP {ip_address}")

        # Update the request status to 'approved'
        cursor.execute(
            """
            UPDATE expense_requests
            SET status = 'approved', updated_at = NOW()
            WHERE request_id = %s
        """,
            (request_id,),
        )

        db = get_db()
        db.commit()
        logger.info(f"Expense approval completed successfully by user '{username}' (ID: {user_id}), Request ID: {request_id}, Expense ID: {expense_id} from IP {ip_address}")
        flash("Expense approved and updated for all participants.", "success")
    except Exception as e:
        db = get_db()
        db.rollback()
        logger.error(f"Expense approval failed for user '{username}' (ID: {user_id}), Request ID: {request_id}: {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error approving expense request: {e}")
        flash("An error occurred.", "danger")
    finally:
        cursor.close()
    return redirect(url_for("dashboard.index"))


# Reject Expense Request
@expenses_bp.route("/reject-expense-request", methods=["POST"])
@login_required
def reject_expense_request():
    request_id = bleach.clean(request.form.get("request_id"))
    user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Expense rejection attempt by user '{username}' (ID: {user_id}), Request ID: {request_id} from IP {ip_address}")
    
    # Use logged cursor instead of regular cursor
    cursor = get_logged_cursor()
    
    try:
        # Only allow the intended user to reject
        cursor.execute(
            """
            UPDATE expense_requests
            SET status = 'rejected', updated_at = NOW()
            WHERE request_id = %s AND to_user_id = %s AND status = 'pending'
        """,
            (request_id, user_id),
        )
        
        if cursor.rowcount > 0:
            db = get_db()
            db.commit()
            logger.info(f"Expense rejection completed successfully by user '{username}' (ID: {user_id}), Request ID: {request_id} from IP {ip_address}")
            flash("Expense request rejected.", "info")
        else:
            logger.warning(f"Invalid expense rejection attempt by user '{username}' (ID: {user_id}), Request ID: {request_id} - request not found or already handled from IP {ip_address}")
            flash("Request not found or already handled.", "warning")
            
    except Exception as e:
        db = get_db()
        db.rollback()
        logger.error(f"Expense rejection failed for user '{username}' (ID: {user_id}), Request ID: {request_id}: {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error rejecting expense request: {e}")
        flash("An error occurred.", "danger")
    finally:
        cursor.close()
    return redirect(url_for("dashboard.index"))

# Edit Expense
@expenses_bp.route("/edit-card/<int:expense_id>", methods=["GET", "POST"])
@login_required
def edit_expense(expense_id):
    userid = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Expense edit page accessed by user '{username}' (ID: {userid}), Expense ID: {expense_id} from IP {ip_address}")

    userCategories = load_categories(userid)

    # Use logged cursor instead of regular cursor
    cursor = get_logged_cursor(dictionary=True)

    try:
        # Retrieve existing expense ID and populate
        cursor.execute(
            """SELECT e.expense_id, e.user_id, e.amount, e.transaction_date, e.category_id, e.description, e.payment_method, c.category as category_name, c.type as category_type FROM expenses e LEFT JOIN categories c on e.category_id = c.category_id WHERE e.user_id = %s AND e.expense_id = %s""",
            (userid, expense_id),
        )
        editExpense = cursor.fetchone()
        
        if not editExpense:
            logger.warning(f"Unauthorized expense edit attempt by user '{username}' (ID: {userid}), Expense ID: {expense_id} - expense not found or not owned by user from IP {ip_address}")
            flash("Expense not found or access denied.", "danger")
            return redirect(url_for("dashboard.index"))
        
        logger.info(f"Expense data loaded for editing by user '{username}' (ID: {userid}), Expense ID: {expense_id}, Amount: {editExpense['amount']} from IP {ip_address}")
    except Exception as e:
        logger.error(f"Error loading expense for edit by user '{username}' (ID: {userid}), Expense ID: {expense_id}: {str(e)} from IP {ip_address}")
        flash("Error loading expense data.", "danger")
        return redirect(url_for("dashboard.index"))
    finally:
        cursor.close()

    if request.method == "POST":
        paymethod = bleach.clean(request.form.get("method"))
        date = bleach.clean(request.form.get("date"))
        amount = bleach.clean(str(request.form.get("amount")))
        category = bleach.clean(request.form.get("category"))
        description = bleach.clean(request.form.get("description"))
        logger.info(f"Expense edit attempt by user '{username}' (ID: {userid}), Expense ID: {expense_id} from IP {ip_address}")

        # Log form data for security monitoring
        logger.info(f"Expense edit form data - User: '{username}' (ID: {userid}), Expense ID: {expense_id}, New Amount: '{amount}', New Category: '{category}' from IP {ip_address}")

        # Backend validation check for empty fields
        if not paymethod or not date or not amount or not category or not description:
            logger.warning(f"Expense edit failed - missing required fields for user '{username}' (ID: {userid}), Expense ID: {expense_id} from IP {ip_address}")
            error_message = "All fields are required!"
            return render_template("edit-card.html", error_message=error_message, expense=editExpense, categories=userCategories)

        # Validate and convert amount
        try:
            original_amount = amount
            amount = float(amount.replace("$", "").replace(",", ""))
            logger.info(f"Amount validation successful for expense edit by user '{username}' (ID: {userid}), Expense ID: {expense_id}: '{original_amount}' -> {amount} from IP {ip_address}")
        except ValueError:
            logger.warning(f"Invalid amount format for expense edit by user '{username}' (ID: {userid}), Expense ID: {expense_id}: '{amount}' from IP {ip_address}")
            error_message = "Invalid amount!"
            return render_template("edit-card.html", error_message=error_message, expense=editExpense, categories=userCategories)

        # Validate date input
        try:
            parsed_date = datetime.datetime.strptime(date, "%Y-%m-%d")
            if parsed_date.date() > datetime.datetime.now().date():
                raise ValueError("Expense Date cannot be in the future")
            logger.info(f"Date validation successful for expense edit by user '{username}' (ID: {userid}), Expense ID: {expense_id}: {date} from IP {ip_address}")
        except ValueError as e:
            logger.warning(f"Invalid date for expense edit by user '{username}' (ID: {userid}), Expense ID: {expense_id}: '{date}' - {str(e)} from IP {ip_address}")
            error_message = "Invalid Date! Please input a valid Date"
            return render_template("edit-card.html", error_message=error_message, expense=editExpense, categories=userCategories)

        # Use logged cursor for database operations
        cursor = get_logged_cursor(dictionary=True)
        
        try:
            # Check if category exists in table
            cursor.execute(
                "SELECT category_id FROM categories WHERE category = %s AND (type = 'Default' or user_id = %s)",
                (category, userid),
            )
            category_exists = cursor.fetchone()

            # Insert new category defined by user
            if not category_exists:
                cursor.execute(
                    "INSERT INTO categories (category, user_id, type) VALUES (%s, %s, %s)",
                    (category, userid, "Custom"),
                )
                db = get_db()
                db.commit()
                category_id = cursor.lastrowid
                logger.info(f"New custom category created during expense edit by user '{username}' (ID: {userid}): '{category}' (Category ID: {category_id}) from IP {ip_address}")
            else:
                category_id = category_exists["category_id"]
                logger.info(f"Using existing category for expense edit by user '{username}' (ID: {userid}): '{category}' (Category ID: {category_id}) from IP {ip_address}")

            # Log the changes being made
            logger.info(f"Updating expense for user '{username}' (ID: {userid}), Expense ID: {expense_id}: Amount: {editExpense['amount']} -> {amount}, Category: {editExpense['category_name']} -> {category} from IP {ip_address}")

            # Update the expense record
            cursor.execute(
                "UPDATE expenses SET amount = %s, description = %s, category_id = %s, payment_method = %s, transaction_date = %s WHERE user_id = %s AND expense_id = %s",
                (amount, description, category_id, paymethod, date, userid, expense_id),
            )
            
            if cursor.rowcount > 0:
                db = get_db()
                db.commit()
                logger.info(f"Expense updated successfully by user '{username}' (ID: {userid}), Expense ID: {expense_id} from IP {ip_address}")
                flash("Expense Updated.", "success")
            else:
                logger.warning(f"Expense update failed - no rows affected for user '{username}' (ID: {userid}), Expense ID: {expense_id} from IP {ip_address}")
                flash("Failed to update expense.", "danger")

        except Exception as e:
            db = get_db()
            db.rollback()
            logger.error(f"Expense update failed for user '{username}' (ID: {userid}), Expense ID: {expense_id}: {str(e)} from IP {ip_address}")
            current_app.logger.error(f"Failed to update expense: {e}")
            flash("Internal error. Try again.", "danger")
        finally:
            cursor.close()

        return redirect(url_for("expenses.expense_add_succesful"))

    return render_template(
        "edit-card.html", expense=editExpense, categories=userCategories
    )