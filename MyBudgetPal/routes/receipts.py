from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from utils.decorators import login_required
from utils.helpers import get_db, get_logged_cursor
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from google import genai
from utils.logging_config import setup_logger, get_user_context

import base64
import requests
import os
import datetime
import ast
import bleach
import logging

receipts_bp = Blueprint('receipts', __name__)

# Setup logging
logger = setup_logger("receipts")

@receipts_bp.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.warning(f"File size limit exceeded - User '{username}' (ID: {user_id}) from IP {ip_address}")
    flash("File is too large. Maximum allowed size is 5MB.", "danger")
    current_app.logger.error(f"File too large error: {error}")
    return redirect(request.url)

@receipts_bp.route("/upload-receipt", methods=["GET", "POST"])
@login_required

def upload_receipt():
    user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr

    # Ensure upload directory exists
    os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)

    if request.method == "POST":
        logger.info(f"Receipt upload attempt by user '{username}' (ID: {user_id}) from IP {ip_address}")
        
        file = request.files.get("receipt_image")
        if not file:
            logger.warning(f"No file provided in upload attempt by user '{username}' (ID: {user_id}) from IP {ip_address}")
            flash("No file uploaded", "danger")
            return redirect(request.url)

        # Log file details for security monitoring
        original_filename = file.filename
        file_size = len(file.read())
        file.seek(0)  # Reset file pointer after reading
        
        logger.info(f"File upload details - User: '{username}' (ID: {user_id}), Original filename: '{original_filename}', Size: {file_size} bytes, IP: {ip_address}")

        # Validate file type
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff'}
        if '.' not in original_filename or original_filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
            logger.warning(f"Invalid file type uploaded by user '{username}' (ID: {user_id}): '{original_filename}' from IP {ip_address}")
            flash("Invalid file type. Please upload an image file.", "danger")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        if filename != original_filename:
            logger.info(f"Filename sanitized for user '{username}' (ID: {user_id}): '{original_filename}' -> '{filename}' from IP {ip_address}")

        file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
        
        try:
            file.save(file_path)
            logger.info(f"File saved successfully for user '{username}' (ID: {user_id}): '{filename}' from IP {ip_address}")

        except Exception as e:
            logger.error(f"File save failed for user '{username}' (ID: {user_id}): '{filename}' - Error: {str(e)} from IP {ip_address}")
            flash("Failed to save uploaded file.", "danger")
            return redirect(request.url)

        try:
            with open(file_path, "rb") as image_file:
                content = base64.b64encode(image_file.read()).decode("utf-8")
            
            # Delete the file after reading
            os.remove(file_path)
            logger.info(f"Temporary file cleaned up for user '{username}' (ID: {user_id}): '{filename}' from IP {ip_address}")

        except Exception as e:
            logger.error(f"File processing failed for user '{username}' (ID: {user_id}): '{filename}' - Error: {str(e)} from IP {ip_address}")
            flash("Failed to process uploaded file.", "danger")
            return redirect(request.url)

        # Log API call attempt
        logger.info(f"Initiating Vision API call for user '{username}' (ID: {user_id}) from IP {ip_address}")
        
        api_url = (
            f"https://vision.googleapis.com/v1/images:annotate?key={current_app.config['GOOGLE_API_KEY']}"
        )
        payload = {
            "requests": [
                {
                    "image": {"content": content},
                    "features": [{"type": "TEXT_DETECTION"}],
                }
            ]
        }

        try:
            response = requests.post(api_url, json=payload)
            result = response.json()
            
            if "error" in result.get("responses", [{}])[0]:
                error_msg = result['responses'][0]['error']['message']
                logger.error(f"Vision API error for user '{username}' (ID: {user_id}): {error_msg} from IP {ip_address}")
                flash(f"Error from Vision API: {error_msg}", "danger")
                return redirect(request.url)
            else:
                logger.info(f"Vision API call successful for user '{username}' (ID: {user_id}) from IP {ip_address}")
                
        except Exception as e:
            logger.error(f"Vision API request failed for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")
            flash("Failed to process receipt image.", "danger")
            return redirect(request.url)

        text = (
            result["responses"][0]
            .get("textAnnotations", [{}])[0]
            .get("description", "")
        )

        # Log OCR text extraction
        logger.info(f"OCR text extracted for user '{username}' (ID: {user_id}), text length: {len(text)} characters from IP {ip_address}")

        success, receipt_id = process_receipt_text(text)

        if not success or not receipt_id:
            logger.error(f"Receipt processing failed for user '{username}' (ID: {user_id}) from IP {ip_address}")
            flash("Receipt processing failed. Please try again.", "danger")
            return redirect(url_for("receipts.upload_receipt_error"))

        # Use logged cursor for database status update
        cursor = get_logged_cursor()
        
        try:
            status = "processed" if success else "failed"
            cursor.execute(
                "UPDATE receipts SET status = %s WHERE receipt_id = %s;",
                (status, receipt_id),
            )
            db = get_db()
            db.commit()
            
            logger.info(f"Receipt processing completed successfully for user '{username}' (ID: {user_id}), Receipt ID: {receipt_id} from IP {ip_address}")
            return redirect(url_for("receipts.upload_receipt_success"))

        except Exception as e:
            db = get_db()
            db.rollback()
            logger.error(f"Database update failed for user '{username}' (ID: {user_id}), Receipt ID: {receipt_id} - Error: {str(e)} from IP {ip_address}")
            current_app.logger.error(f"Failed to update receipt status: {str(e)}")
            flash("Failed to update receipt status in database.", "warning")
            return redirect(url_for("receipts.upload_receipt_error"))

        finally:
            cursor.close()

    return render_template("upload-receipt.html")


def process_receipt_text(text):
    user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Starting receipt text processing for user '{username}' (ID: {user_id}) from IP {ip_address}")

    try:
        # Use logged cursor instead of regular cursor
        cursor = get_logged_cursor(dictionary=True)

        # Log database query for categories
        logger.info(f"Fetching categories for user '{username}' (ID: {user_id}) from IP {ip_address}")
        
        cursor.execute(
            """
                    SELECT DISTINCT category, category_id FROM categories WHERE type = 'Default'
                    UNION 
                    SELECT DISTINCT category, category_id FROM categories WHERE type = 'Custom' AND user_id = %s;
                """,
            (session.get("user_id"),),
        )

        categories = cursor.fetchall()
        logger.info(f"Retrieved {len(categories)} categories for user '{username}' (ID: {user_id}) from IP {ip_address}")

        # Log AI API call
        logger.info(f"Initiating Gemini AI call for receipt processing - user '{username}' (ID: {user_id}) from IP {ip_address}")
        client = genai.Client(api_key=current_app.config["GOOGLE_API_KEY"])

        prompt = f"""
            I am developing a personal budget tracking web application. 
            I have an upload receipt feature in the application that allows users to upload receipt images that will be processed by an OCR API to extract the text on the receipt.
            I am going to send you the extracted text from the API. 
            I need your help to extract the details on the receipt so that I can insert them into the database.
            I have the following fields in my database: raw_text, vendor_name, date, amount, payment_method, and category. 
            For the category field, I have the following default categories:
            {categories}
            Choose the most suitable category in this list or create a new category if the item does not match any in the list.
            For the payment_method field, I have the following default payment methods: Cash, Debit Card, Credit Card, Bank Transfer. 
            If the payment method is 'paynow'or 'paylah', the payment_method field will be 'Bank Transfer'.
            Choose the most suitable payment method from this list or indicate "Other" if it does not exist.
            For the date field, please use the format YYYY-MM-DD.
            Please ensure that the amount is a valid decimal number with 2 decimal places and does not contain any currency symbols or commas.
            Please help me extract these details and return them as a python dictionary list for me to conduct further processing. 
            The response should only contain the list without any extra quotes and nothing else.
            Here is the extracted text:
            {text}
        """

        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
            )
            logger.info(f"Gemini AI response received for user '{username}' (ID: {user_id}) from IP {ip_address}")

        except Exception as e:
            logger.error(f"Gemini AI call failed for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")
            cursor.close()
            return False, None

        try:
            cleaned_text = response.text.removeprefix("```python\n").removesuffix(
                "\n```"
            )
            receipt_list = ast.literal_eval(cleaned_text)
            receipt = receipt_list[0]
            logger.info(f"AI response parsed successfully for user '{username}' (ID: {user_id}) from IP {ip_address}")

        except Exception as e:
            logger.error(f"AI parsing failed for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")
            current_app.logger.error(f"AI parsing failed: {str(e)}")
            cursor.close()
            return False, None

        receipt = receipt_list[0]

        raw_text = bleach.clean(str(receipt["raw_text"]))
        vendor_name = bleach.clean(str(receipt["vendor_name"]))
        date = bleach.clean(str(receipt["date"]))
        amount = bleach.clean(str(receipt["amount"]))
        payment_method = bleach.clean(str(receipt["payment_method"]))
        category = bleach.clean(str(receipt["category"]))

        logger.info(f"Extracted receipt data for user '{username}' (ID: {user_id}): vendor='{vendor_name}', amount='{amount}', date='{date}', category='{category}' from IP {ip_address}")

        # INSERT INTO receipts table
        if raw_text and vendor_name and date and amount and payment_method and category:

            # Ensure amount is a valid decimal number
            try:
                amount = float(amount)  # Convert amount to float
                if amount < 0:
                    logger.error(f"Invalid amount format for user '{username}' (ID: {user_id}): '{amount}' from IP {ip_address}")
                    current_app.logger.error("Invalid amount format in receipt processing")
                    cursor.close()
                    return False, None
                logger.info(f"Amount validation successful for user '{username}' (ID: {user_id}): {amount} from IP {ip_address}")

            except ValueError:
                logger.error(f"Invalid amount format for user '{username}' (ID: {user_id}): '{amount}' from IP {ip_address}")
                current_app.logger.error("Invalid amount format in receipt processing")
                cursor.close()
                return False, None

            # Ensure date is in the correct format
            try:
                date = datetime.datetime.strptime(date, "%Y-%m-%d").date()
                logger.info(f"Date validation successful for user '{username}' (ID: {user_id}): {date} from IP {ip_address}")

            except ValueError:
                logger.error(f"Invalid date format for user '{username}' (ID: {user_id}): '{date}' from IP {ip_address}")
                current_app.logger.error("Invalid date format in receipt processing")
                cursor.close()
                return False, None

            # Insert receipt details into the database
            try:
                cursor.execute(
                    """
                            INSERT INTO receipts (user_id, receipt_date, extracted_text, vendor_name, total_amount, status) 
                            VALUES (%s, %s, %s, %s, %s, %s);
                        """,
                    (
                        session.get("user_id"),
                        date,
                        raw_text,
                        vendor_name,
                        amount,
                        "pending",
                    ),
                )

                receipt_id = cursor.lastrowid
                db = get_db()
                db.commit()
                logger.info(f"Receipt inserted into database for user '{username}' (ID: {user_id}), Receipt ID: {receipt_id} from IP {ip_address}")

            except Exception as e:
                db = get_db()
                db.rollback()
                logger.error(f"Receipt database insertion failed for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")
                cursor.close()
                return False, None

            # Check the validity of the category
            if not any(item["category"] == category for item in categories):
                try:
                    cursor.execute(
                        """
                                INSERT INTO categories (category, user_id, type) 
                                VALUES (%s, %s, 'Custom');
                            """,
                        (category, session.get("user_id")),
                    )
                    db = get_db()
                    db.commit()
                    logger.info(f"New custom category created for user '{username}' (ID: {user_id}): '{category}' from IP {ip_address}")
                except Exception as e:
                    db = get_db()
                    db.rollback()
                    logger.error(f"Custom category creation failed for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")

            # INSERT INTO expenses table
            try:
                cursor.execute(
                    """
                    INSERT INTO expenses (user_id, amount, transaction_date, category_id, description, payment_method) 
                    VALUES (%s, %s, %s, 
                        (SELECT category_id FROM categories 
                        WHERE category = %s AND (user_id = %s OR type = 'Default')
                        LIMIT 1), 
                        %s, %s);
                """,
                    (
                        session.get("user_id"),
                        amount,
                        date,
                        category,
                        session.get("user_id"),
                        vendor_name,
                        payment_method,
                    ),
                )

                db = get_db()
                db.commit()
                logger.info(f"Expense record created for user '{username}' (ID: {user_id}), Amount: {amount}, Category: '{category}' from IP {ip_address}")
                cursor.close()
                return True, receipt_id
            
            except Exception as e:
                db = get_db()
                db.rollback()
                logger.error(f"Expense creation failed for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")
                cursor.close()
                return False, None

        else:
            logger.error(f"Incomplete receipt data for user '{username}' (ID: {user_id}) from IP {ip_address}")
            current_app.logger.error("Incomplete receipt data")
            cursor.close()
            return False, None

    except Exception as e:
        logger.error(f"Receipt processing error for user '{username}' (ID: {user_id}): {str(e)} from IP {ip_address}")
        current_app.logger.error(f"Error processing receipt: {str(e)}")
        flash(
            "An error occurred while processing the receipt. Please try again.",
            "danger",
        )
        return False, None

@receipts_bp.route("/upload-receipt-success")
@login_required
def upload_receipt_success():
    user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Receipt upload success page accessed by user '{username}' (ID: {user_id}) from IP {ip_address}")
    return render_template("upload-receipt-successful.html")


@receipts_bp.route("/upload-receipt-error")
@login_required
def upload_receipt_error():
    user_id = session.get("user_id")
    username = session.get("username")
    ip_address = request.remote_addr
    
    logger.info(f"Receipt upload error page accessed by user '{username}' (ID: {user_id}) from IP {ip_address}")
    return render_template("upload-receipt-failed.html")