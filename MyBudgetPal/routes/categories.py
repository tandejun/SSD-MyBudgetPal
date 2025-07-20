from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from utils.helpers import get_db, load_categories, load_custom_categories, get_week_range
from utils.decorators import login_required
from utils.logging_config import setup_logger, get_user_context
import datetime
import json
from decimal import Decimal
import bleach
import logging
import os

categories_bp = Blueprint("categories", __name__)

# Set up logging
logger = setup_logger("categories")

@categories_bp.route("/categories", methods=["GET", "POST"])
@login_required
def categories():
    # Get user_id for all methods
    userid = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Categories page accessed by user '{username}' (ID: {userid}) from IP {ip_address}")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)

    # Load All Categories - Default, Custom
    userCategories = load_custom_categories(userid)
    
    logger.info(f"Categories loaded for user '{username}' (ID: {userid}): {len(userCategories)} categories from IP {ip_address}")

    try:
        if request.method == "POST":
            categoryId = bleach.clean(request.form.get("delete_category_id"))
            
            logger.info(f"Category deletion attempt by user '{username}' (ID: {userid}), category ID: {categoryId} from IP {ip_address}")
            
            # Check if category exists and belongs to user before deletion
            cursor.execute(
                "SELECT category FROM categories WHERE category_id=%s AND user_id=%s",
                (categoryId, userid),
            )
            category_to_delete = cursor.fetchone()
            
            if not category_to_delete:
                logger.warning(f"Category deletion failed - not found or unauthorized: user '{username}' (ID: {userid}), category ID: {categoryId} from IP {ip_address}")
                flash("Category not found or unauthorized.", "danger")
                return redirect(url_for("categories.categories"))
            
            cursor.execute(
                "DELETE FROM categories WHERE category_id=%s AND user_id=%s",
                (categoryId, userid),
            )
            
            rows_affected = cursor.rowcount
            db.commit()
            
            if rows_affected > 0:
                logger.info(f"Category deleted successfully by user '{username}' (ID: {userid}), category '{category_to_delete['category']}' (ID: {categoryId}), rows affected: {rows_affected} from IP {ip_address}")
                flash("Category deleted successfully!", "success")
            else:
                logger.warning(f"Category deletion failed - no rows affected: user '{username}' (ID: {userid}), category ID: {categoryId} from IP {ip_address}")
                flash("Category deletion failed.", "warning")
            
            # Refresh page after deletion to reflect changes
            return redirect(url_for("categories.categories"))
            
    except Exception as e:
        db.rollback()
        logger.error(f"Category deletion failed for user '{username}' (ID: {userid}), category ID: {categoryId}: {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error deleting category: {e}")
        flash("An error occurred while deleting the category.", "danger")
    finally:
        cursor.close()

    return render_template("categories.html", userCat=userCategories)


@categories_bp.route("/add_category", methods=["POST"])
@login_required
def add_category():
    userid = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    db = get_db()
    cursor = db.cursor(dictionary=True)

    if request.method == "POST":
        category = bleach.clean(request.form.get("category"))
        category_type = bleach.clean(request.form.get("type", "Custom"))
        
        logger.info(f"Category addition attempt by user '{username}' (ID: {userid}), category: '{category}', type: '{category_type}' from IP {ip_address}")

        # Add validation
        if not category:
            logger.warning(f"Category addition failed - empty name: user '{username}' (ID: {userid}) from IP {ip_address}")
            flash("Category name is required", "error")
            return redirect(request.referrer)

        try:
            # Check if custom category already exists
            cursor.execute(
                "SELECT category_id FROM categories WHERE category = %s AND user_id = %s",
                (category, userid),
            )
            if cursor.fetchone():
                logger.warning(f"Category addition failed - duplicate custom category: user '{username}' (ID: {userid}), category: '{category}' from IP {ip_address}")
                flash("Category already exists", "error")
                return redirect(request.referrer)

            # Check if default category already exists
            cursor.execute(
                "SELECT category FROM categories WHERE category = %s and type = 'Default'",
                (category,),
            )
            if cursor.fetchone():
                logger.warning(f"Category addition failed - conflicts with default category: user '{username}' (ID: {userid}), category: '{category}' from IP {ip_address}")
                flash("Category conflicts with default category", "error")
                return redirect(request.referrer)

            # Insert new category
            cursor.execute(
                "INSERT INTO categories (category, user_id, type) VALUES (%s, %s, %s)",
                (category, userid, category_type),
            )
            
            new_category_id = cursor.lastrowid
            db.commit()

            logger.info(f"Category added successfully by user '{username}' (ID: {userid}), category: '{category}' (ID: {new_category_id}), type: '{category_type}' from IP {ip_address}")
            flash("Category added successfully!", "success")
            
        except Exception as e:
            db.rollback()
            logger.error(f"Category addition failed for user '{username}' (ID: {userid}), category: '{category}': {str(e)} from IP {ip_address}")
            current_app.logger.error(f"Error adding category: {e}")
            flash("An error occurred while adding the category.", "danger")
        finally:
            cursor.close()

        return redirect(request.referrer)


# Edit Category
@categories_bp.route("/edit_category/<int:category_id>", methods=["GET", "POST"])
@login_required
def edit_category(category_id):
    userid = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Category edit page accessed by user '{username}' (ID: {userid}), category ID: {category_id} from IP {ip_address}")
    
    db = get_db()
    cursor = db.cursor(dictionary=True)

    try:
        cursor.execute(
            """SELECT * FROM categories WHERE category_id=%s and user_id=%s""",
            (category_id, userid),
        )
        editCategory = cursor.fetchone()
        
        if not editCategory:
            logger.warning(f"Category edit failed - not found or unauthorized: user '{username}' (ID: {userid}), category ID: {category_id} from IP {ip_address}")
            flash("Category not found or unauthorized.", "danger")
            return redirect(url_for("categories.categories"))

        if request.method == "POST":
            categoryName = bleach.clean(request.form.get("category"))
            old_category_name = editCategory['category']
            
            logger.info(f"Category edit attempt by user '{username}' (ID: {userid}), category ID: {category_id}, old name: '{old_category_name}', new name: '{categoryName}' from IP {ip_address}")

            try:
                # Check if category name already exists as custom category (excluding current one)
                cursor.execute(
                    "SELECT category_id FROM categories WHERE category = %s AND user_id = %s AND category_id != %s",
                    (categoryName, userid, category_id),
                )
                if cursor.fetchone():
                    logger.warning(f"Category edit failed - duplicate custom category: user '{username}' (ID: {userid}), category ID: {category_id}, name: '{categoryName}' from IP {ip_address}")
                    flash("Category name already exists", "error")
                    return redirect(request.referrer)

                # Check if category name already exists as default category
                cursor.execute(
                    "SELECT category_id FROM categories WHERE category = %s AND type = 'Default'",
                    (categoryName,),
                )
                if cursor.fetchone():
                    logger.warning(f"Category edit failed - conflicts with default category: user '{username}' (ID: {userid}), category ID: {category_id}, name: '{categoryName}' from IP {ip_address}")
                    flash("Category conflicts with default category", "error")
                    return redirect(request.referrer)

                # If no issues --> update category values in database
                cursor.execute(
                    """UPDATE categories SET category = %s WHERE category_id=%s AND user_id=%s""",
                    (categoryName, category_id, userid),
                )
                
                rows_affected = cursor.rowcount
                db.commit()
                
                if rows_affected > 0:
                    logger.info(f"Category edited successfully by user '{username}' (ID: {userid}), category ID: {category_id}, changed from '{old_category_name}' to '{categoryName}', rows affected: {rows_affected} from IP {ip_address}")
                    flash("Category updated successfully!", "success")
                else:
                    logger.warning(f"Category edit failed - no rows affected: user '{username}' (ID: {userid}), category ID: {category_id} from IP {ip_address}")
                    flash("Category update failed.", "warning")

            except Exception as e:
                db.rollback()  # In case of failure
                logger.error(f"Category edit failed for user '{username}' (ID: {userid}), category ID: {category_id}: {str(e)} from IP {ip_address}")
                current_app.logger.error(f"Failed to edit category: {e}")
                flash("Internal error. Try again.", "danger")
            finally:
                cursor.close()

            return redirect(url_for("categories.categories"))

    except Exception as e:
        logger.error(f"Category edit page loading failed for user '{username}' (ID: {userid}), category ID: {category_id}: {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error loading category edit page: {e}")
        flash("An error occurred while loading the category.", "danger")
        return redirect(url_for("categories.categories"))
    finally:
        if 'cursor' in locals():
            cursor.close()

    return render_template("categories.html")