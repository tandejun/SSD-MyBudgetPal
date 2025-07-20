from decimal import Decimal
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from utils.decorators import login_required
from utils.helpers import get_db, get_progress_color, get_week_range, calculate_change, check_2fa_status
from utils.logging_config import setup_logger, get_user_context
import bleach
import logging
import os
import json
import datetime

dashboard_bp = Blueprint("dashboard", __name__)

# Set up logging
logger = setup_logger("dashboard")

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super(DecimalEncoder, self).default(obj)

# Main Page
@dashboard_bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    # Need to retrieve expense amount, date, category, description and payment method based on user
    userid = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Dashboard accessed by user '{username}' (ID: {userid}) from IP {ip_address}")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        # Retrieve daily, monthly, and yearly expenses here
        cursor.execute(
            """
            SELECT
                -- Daily
                COALESCE(SUM(CASE WHEN DATE(transaction_date) = CURDATE() THEN amount END), 0) AS today_expense,
                COALESCE(SUM(CASE WHEN DATE(transaction_date) = CURDATE() - INTERVAL 1 DAY THEN amount END), 0) AS yesterday_expense,

                -- Monthly
                COALESCE(SUM(CASE WHEN YEAR(transaction_date) = YEAR(CURDATE()) AND MONTH(transaction_date) = MONTH(CURDATE()) THEN amount END), 0) AS this_month_expense,
                COALESCE(SUM(CASE WHEN YEAR(transaction_date) = YEAR(CURDATE() - INTERVAL 1 MONTH) AND MONTH(transaction_date) = MONTH(CURDATE() - INTERVAL 1 MONTH) THEN amount END), 0) AS last_month_expense,

                -- Yearly
                COALESCE(SUM(CASE WHEN YEAR(transaction_date) = YEAR(CURDATE()) THEN amount END), 0) AS this_year_expense,
                COALESCE(SUM(CASE WHEN YEAR(transaction_date) = YEAR(CURDATE()) - 1 THEN amount END), 0) AS last_year_expense
            FROM expenses
            WHERE user_id = %s
            """,
            (userid,),
        )

        dailyMonthlyYearlyExpenses = cursor.fetchone()

        # Example
        todayChange = calculate_change(
            dailyMonthlyYearlyExpenses["today_expense"],
            dailyMonthlyYearlyExpenses["yesterday_expense"],
        )
        monthChange = calculate_change(
            dailyMonthlyYearlyExpenses["this_month_expense"],
            dailyMonthlyYearlyExpenses["last_month_expense"],
        )
        yearChange = calculate_change(
            dailyMonthlyYearlyExpenses["this_year_expense"],
            dailyMonthlyYearlyExpenses["last_year_expense"],
        )

        logger.info(f"Expense summary calculated for user '{username}' (ID: {userid}): Today: {dailyMonthlyYearlyExpenses['today_expense']}, Month: {dailyMonthlyYearlyExpenses['this_month_expense']}, Year: {dailyMonthlyYearlyExpenses['this_year_expense']} from IP {ip_address}")

        # Retrieve user expenses here
        cursor.execute(
            """SELECT e.expense_id, e.user_id, e.amount, e.transaction_date, e.category_id, e.description, e.payment_method, e.split_from, c.category as category_name, c.type as category_type, c.icon AS icon, c.icon_colour as colour FROM expenses e LEFT JOIN categories c on e.category_id = c.category_id WHERE e.user_id = %s ORDER BY e.transaction_date DESC""",
            (userid,),
        )
        userExpenses = cursor.fetchall()

        # Find expenses where current user is involved
        cursor.execute(
            """
            SELECT DISTINCT 
                CASE 
                    WHEN split_from IS NULL THEN expense_id 
                    ELSE split_from 
                END as original_expense_id
            FROM expenses 
            WHERE user_id = %s 
            """,
            (userid,),
        )
        relevant_expense_ids = [row["original_expense_id"] for row in cursor.fetchall()]

        my_split_info = []
        for original_id in relevant_expense_ids:
            # Get original user
            cursor.execute(
                "SELECT user_id FROM expenses WHERE expense_id = %s", (original_id,)
            )
            original_result = cursor.fetchone()
            if not original_result:
                continue

            original_user = original_result["user_id"]

            # Get all split users
            cursor.execute(
                "SELECT user_id FROM expenses WHERE split_from = %s", (original_id,)
            )
            split_users = [row["user_id"] for row in cursor.fetchall()]

            # Combine original + split users for complete list
            all_user_ids = [original_user] + split_users

            # Only include if this expense has splits and current user is involved
            if split_users and userid in all_user_ids:
                my_split_info.append(
                    {
                        "original_expense_id": original_id,
                        "original_user_id": original_user,
                        "split_user_ids": split_users,
                        "all_involved_user_ids": all_user_ids,  # This has EVERYONE
                    }
                )

        # Currently, all_involved_user_ids will have all the involved users
        # for that record, i will just get the user_id that is not mine

        print(f"My split expenses with all users:", my_split_info)

        # Get expense IDs from your split info
        split_expense_ids = [item["original_expense_id"] for item in my_split_info]

        if split_expense_ids:
            cursor.execute(
                f"""
                SELECT * FROM expenses 
                WHERE expense_id IN ({','.join(['%s'] * len(split_expense_ids))})
                ORDER BY transaction_date DESC
            """,
                split_expense_ids,
            )
            allSplit = cursor.fetchall()
        else:
            allSplit = []

        split_info_map = {item["original_expense_id"]: item for item in my_split_info}

        expenses_with_split_info = []
        for expense in allSplit:  # your main expenses query
            expense_data = dict(expense) 

            # Check if this expense has split information
            if expense["expense_id"] in split_info_map:
                split_info = split_info_map[expense["expense_id"]]

                # Get all involved users except the current user
                other_user_ids = [
                    uid for uid in split_info["all_involved_user_ids"] if uid != userid
                ]

                if other_user_ids:
                    # Get usernames for the other users
                    cursor.execute(
                        "SELECT user_id, username FROM users WHERE user_id IN ({})".format(
                            ",".join(["%s"] * len(other_user_ids))
                        ),
                        other_user_ids,
                    )
                    other_users = cursor.fetchall()

                    # Add split information to expense
                    expense_data["split_with_usernames"] = [
                        user["username"] for user in other_users
                    ]
                    expense_data["is_split"] = True
                else:
                    expense_data["split_with_usernames"] = []
                    expense_data["is_split"] = False
            else:
                expense_data["split_with_usernames"] = []
                expense_data["is_split"] = False

            expenses_with_split_info.append(expense_data)

        print(f"expenses with split info:", expenses_with_split_info)

        # Retrieve expenses based on category
        # This CE will go under monthly expenses breakdown section later
        cursor.execute(
            """SELECT SUM(e.amount) as grouped_amount, c.category as category_name, c.icon_colour as colour FROM expenses e INNER JOIN categories c on e.category_id = c.category_id WHERE e.user_id = %s GROUP BY c.category_id""",
            (userid,),
        )
        categorizedExpenses = cursor.fetchall()

        # Retrieve expenses based on payment method TODO [Not Displayed Yet]
        cursor.execute(
            """SELECT SUM(e.amount) AS grouped_paymethod, e.payment_method AS PM FROM expenses e WHERE user_id = %s GROUP BY PM ORDER BY grouped_paymethod DESC""",
            (userid,),
        )
        payMethodExpenses = cursor.fetchall()

        # Time-based Visualization Section
        cursor.execute(
            """SELECT 
        YEAR(transaction_date) AS Year,
        WEEK(transaction_date, 1) AS Week, 
        COUNT(expense_id) AS Expense,
        SUM(expenses.amount) AS 'Total Weekly Expenses'
        FROM mybudgetpal.expenses
        WHERE user_id = %s
        GROUP BY Year, Week
        ORDER BY Year, Week;""",
            (userid,),
        )
        weeklyExpenses = cursor.fetchall()

        for expense in weeklyExpenses:
            expense["week_display"] = get_week_range(expense["Year"], expense["Week"])

        weekly_expenses_json = json.dumps(weeklyExpenses, cls=DecimalEncoder)

        # Categorized Expenses
        total_expenses = sum(cat["grouped_amount"] for cat in categorizedExpenses)
        for category in categorizedExpenses:
            category["percentage"] = (
                (category["grouped_amount"] / total_expenses * 100)
                if total_expenses > 0
                else 0
            )

        # Get Lifetime Expense Count
        cursor.execute(
            """SELECT SUM(e.amount) AS lifetimeExpense FROM expenses e WHERE user_id=%s""",
            (userid,),
        )
        lifetimeExpense = cursor.fetchone()

        # Grouped Percentage for Paymethod
        total_paymethod = sum(pm["grouped_paymethod"] for pm in payMethodExpenses)
        for pm in payMethodExpenses:
            pm["percentage"] = (
                (pm["grouped_paymethod"] / total_paymethod * 100)
                if total_paymethod > 0
                else 0
            )

        logger.info(f"Dashboard data loaded for user '{username}' (ID: {userid}): {len(userExpenses)} expenses, {len(categorizedExpenses)} categories, {len(split_expense_ids)} split expenses from IP {ip_address}")

        # DELETE Function here
        if request.method == "POST":
            if "delete_expense_id" in request.form:
                expense_id = bleach.clean(request.form["delete_expense_id"])
                
                logger.info(f"Expense deletion attempt by user '{username}' (ID: {userid}), expense ID: {expense_id} from IP {ip_address}")

                try:
                    cursor.execute(
                        """DELETE FROM expenses WHERE expense_id = %s AND user_id = %s""", (expense_id, userid)
                    )
                    rows_affected = cursor.rowcount
                    db.commit()
                    
                    if rows_affected > 0:
                        logger.info(f"Expense deleted successfully by user '{username}' (ID: {userid}), expense ID: {expense_id}, rows affected: {rows_affected} from IP {ip_address}")
                        flash("Expense deleted successfully!", "success")
                        
                        # Redirect to the same page to refresh the data
                        return redirect(url_for("dashboard.index"))
                    else:
                        logger.warning(f"Expense deletion failed - not found or unauthorized: user '{username}' (ID: {userid}), expense ID: {expense_id} from IP {ip_address}")
                        flash("Expense not found!", "warning")
                except Exception as e:
                    db.rollback()
                    logger.error(f"Expense deletion failed for user '{username}' (ID: {userid}), expense ID: {expense_id}: {str(e)} from IP {ip_address}")
                    current_app.logger.error(f"Error deleting expense: {e}")
                    flash("Error deleting expense!", "error")

        # Retrieve pending expense requests for the user
        cursor.execute(
            """
            SELECT er.request_id, er.amount, er.expense_id, er.from_user_id, u.username AS from_username, e.description
            FROM expense_requests er
            JOIN users u ON er.from_user_id = u.user_id
            JOIN expenses e ON er.expense_id = e.expense_id
            WHERE er.to_user_id = %s AND er.status = 'pending'
            ORDER BY er.created_at DESC
        """,
            (userid,),
        )
        expense_requests = cursor.fetchall()

        logger.info(f"Dashboard loaded successfully for user '{username}' (ID: {userid}): {len(expense_requests)} pending expense requests from IP {ip_address}")

    except Exception as e:
        logger.error(f"Dashboard loading failed for user '{username}' (ID: {userid}): {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error loading dashboard: {e}")
        flash("An error occurred while loading the dashboard.", "danger")
        
        # Provide default values in case of error
        userExpenses = []
        categorizedExpenses = []
        payMethodExpenses = []
        weeklyExpenses = []
        weekly_expenses_json = json.dumps([])
        lifetimeExpense = {"lifetimeExpense": 0}
        expense_requests = []
        dailyMonthlyYearlyExpenses = {
            "today_expense": 0,
            "yesterday_expense": 0,
            "this_month_expense": 0,
            "last_month_expense": 0,
            "this_year_expense": 0,
            "last_year_expense": 0
        }
        todayChange = 0
        monthChange = 0
        yearChange = 0
        expenses_with_split_info = []
        
    finally:
        cursor.close()

    # Check for 2FA notification
    try:
        logger.debug(f"Calling check_2fa_status for user {userid}")
        notification_data = check_2fa_status(userid)
        logger.debug(f"check_2fa_status returned: {notification_data}")
        logger.info(f"2FA status checked for user '{username}' (ID: {userid}): show_notification={notification_data.get('show_2fa_notification', False)} from IP {ip_address}")
    except Exception as e:
        logger.error(f"Error checking 2FA status for user '{username}' (ID: {userid}): {str(e)} from IP {ip_address}")
        notification_data = {"show_2fa_notification": False}

    logger.debug(f"Final notification_data being passed to template: {notification_data}")

    return render_template(
        "index.html",
        username=session.get("username"),
        expenses=userExpenses,
        categorizedExps=categorizedExpenses,
        payExps=payMethodExpenses,
        weeklyExps=weeklyExpenses,
        weeklyExpensesJson=weekly_expenses_json,
        lifetimeExps=lifetimeExpense,
        get_progress_color=get_progress_color,
        expense_requests=expense_requests,
        dailyMonthlyYearlyExpenses=dailyMonthlyYearlyExpenses,
        todayChange=todayChange,
        monthChange=monthChange,
        yearChange=yearChange,
        splitInfoExpenses=expenses_with_split_info,
        **notification_data
    )
