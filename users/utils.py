from venv import logger
from .models import ActivityLog
from datetime import datetime

def log_activity(admin_user, action, target_user=None, word_kh=None, word_en=None):
    """
    Log user activity for auditing purposes

    Args:
        admin_user: The admin/superuser performing the action
        action: The action being performed (from ActivityLog.ACTIONS)
        target_user: The user being affected by the action (for user management actions)
        word_kh: Optional Khmer word being affected (for dictionary actions)
        word_en: Optional English word being affected (for dictionary actions)
    """
    from .models import ActivityLog
    import logging
    import traceback

    logger = logging.getLogger(__name__)

    try:
        # Prepare action details if target user is provided
        action_details = None
        if target_user:
            action_details = {
                'user_id': target_user.id,
                'role': target_user.role,
                'sex': getattr(target_user, 'sex', None),
                'position': getattr(target_user, 'position', None),
                'phone_number': getattr(target_user, 'phone_number', None)
            }

        # Create the activity log
        ActivityLog.objects.create(
            user=admin_user,
            username_kh=getattr(admin_user, 'username_kh', ''),
            action=action,
            role=getattr(admin_user, 'role', 'USER'),
            word_kh=word_kh,
            word_en=word_en,
            # Store target user information
            email=getattr(target_user, 'email', None) if target_user else None,
            staff_id=getattr(target_user, 'staff_id', None) if target_user else None,
            username=getattr(target_user, 'username', None) if target_user else None,
            action_details=action_details
        )

        # Log successful activity tracking
        logger.info(f"Activity logged: {action} by {admin_user.username} on {target_user.username if target_user else 'N/A'}")

    except Exception as e:
        # Log the error with traceback for debugging
        logger.error(f"Failed to log activity: {str(e)}")
        logger.error(traceback.format_exc())

def get_mobile_encryption_key():
    """
    Generate a dynamic encryption key based on current year and month
    The template "Ajv!ndfjkhg0${current_year}g0sno%eu$rtg@nejog${current_month}" is fixed,
    only the year and month values change.
    """
    # Get current year and month
    current_year = datetime.now().strftime('%Y')  # Format: YYYY
    current_month = datetime.now().strftime('%m')  # Format: MM

    # Fixed template with placeholders
    key_template = "Ajv!ndfjkhg0${current_year}g0sno%eu$rtg@nejog${current_month}"

    # Replace placeholders with actual values
    dynamic_key = key_template.replace("${current_year}", current_year).replace("${current_month}", current_month)

    # Ensure the key is exactly 32 bytes (for AES-256)
    if len(dynamic_key) < 32:
        # Repeat the key pattern until it's at least 32 bytes
        dynamic_key = (dynamic_key * ((32 // len(dynamic_key)) + 1))[:32]
    elif len(dynamic_key) > 32:
        # Truncate to exactly 32 bytes
        dynamic_key = dynamic_key[:32]

    return dynamic_key

def format_date(date_obj):
    """
    Convert datetime object to 'DD-MM-YYYY' format
    """
    if not date_obj:
        return None
    return date_obj.strftime('%d-%m-%Y')

def convert_to_khmer_number(text):
    """
    Convert Latin numbers to Khmer numbers
    """
    latin_to_khmer = {
        '0': '០',
        '1': '១',
        '2': '២',
        '3': '៣',
        '4': '៤',
        '5': '៥',
        '6': '៦',
        '7': '៧',
        '8': '៨',
        '9': '៩'
    }

    # If input is None or not a string, return as is
    if not isinstance(text, str):
        return text

    # Convert each Latin digit to Khmer
    return ''.join(latin_to_khmer.get(char, char) for char in text)

def convert_to_khmer_date(date_str):
    """
    Convert Gregorian date to Khmer date format

    Args:
        date_str (str): Date in format 'DD-MM-YYYY'

    Returns:
        str: Date in Khmer format 'DD-Month-YYYY'
    """
    # Khmer month names
    khmer_months = {
        '01': 'មករា',
        '02': 'កុម្ភៈ',
        '03': 'មីនា',
        '04': 'មេសា',
        '05': 'ឧសភា',
        '06': 'មិថុនា',
        '07': 'កក្កដា',
        '08': 'សីហា',
        '09': 'កញ្ញា',
        '10': 'តុលា',
        '11': 'វិច្ឆិកា',
        '12': 'ធ្នូ'
    }

    # Khmer number mapping
    khmer_numbers = {
        '0': '០', '1': '១', '2': '២', '3': '៣', '4': '៤',
        '5': '៥', '6': '៦', '7': '៧', '8': '៨', '9': '៩'
    }

    def convert_to_khmer_number(num_str):
        return ''.join(khmer_numbers.get(digit, digit) for digit in num_str)

    try:
        # Split the date
        day, month, year = date_str.split('-')

        # Convert to Khmer
        khmer_day = convert_to_khmer_number(day)
        khmer_month = khmer_months.get(month, month)
        khmer_year = convert_to_khmer_number(year)

        return f"{khmer_day}-{khmer_month}-{khmer_year}"

    except Exception as e:
        # If conversion fails, return original string
        return date_str

def format_phone_number(phone_number):
    """
    Format phone number by splitting into groups of 3 digits
    """
    # Remove any existing spaces or non-digit characters
    cleaned_number = ''.join(filter(str.isdigit, str(phone_number)))

    # Handle different phone number lengths
    if len(cleaned_number) < 9:
        return cleaned_number  # Return original if too short

    # Different formatting based on number length
    if len(cleaned_number) == 9:
        return f"{cleaned_number[:3]} {cleaned_number[3:6]} {cleaned_number[6:]}"
    elif len(cleaned_number) == 10:
        return f"{cleaned_number[:3]} {cleaned_number[3:6]} {cleaned_number[6:]}"
    else:
        return ' '.join([
            cleaned_number[:3],  # First 3 digits
            cleaned_number[3:6],  # Next 3 digits
            cleaned_number[6:]    # Remaining digits
        ])
