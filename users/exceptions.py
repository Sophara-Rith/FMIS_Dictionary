# users/exceptions.py
from rest_framework.views import exception_handler
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework import status
import logging

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """
    Custom exception handler for REST framework that formats error responses
    consistently across the API.
    """
    # Call REST framework's default exception handler
    response = exception_handler(exc, context)

    # Log the exception
    logger.error(f"Exception occurred: {str(exc)}")

    # If this is an AuthenticationFailed exception, customize the response
    if isinstance(exc, AuthenticationFailed):
        return Response({
            'responseCode': status.HTTP_401_UNAUTHORIZED,
            'message': 'Invalid token. Please login again',
            'data': None
        }, status=status.HTTP_401_UNAUTHORIZED)

    # If response is already handled by DRF, format it consistently
    if response is not None:
        # Get the status code
        status_code = response.status_code

        # Format the response
        formatted_response = {
            'responseCode': status_code,
            'message': str(exc),
            'data': None
        }

        # For validation errors, include the details
        if hasattr(response, 'data') and isinstance(response.data, dict):
            if 'detail' in response.data:
                formatted_response['message'] = response.data['detail']
            elif response.data:
                formatted_response['errors'] = response.data

        response.data = formatted_response

    return response
