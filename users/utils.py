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
