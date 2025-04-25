# debug_utils.py
import traceback
import logging
import uuid
from functools import wraps
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status

logger = logging.getLogger(__name__)

def debug_error(func):
    @wraps(func)
    def wrapper(self, request, *args, **kwargs):
        try:
            # Execute the original view method
            return func(self, request, *args, **kwargs)

        except Exception as e:
            # Generate a unique error tracking ID
            error_id = str(uuid.uuid4())

            # Detailed error logging
            error_details = {
                'error_id': error_id,
                'error_type': type(e).__name__,
                'error_message': str(e),
                'endpoint': f"{self.__class__.__name__}.{func.__name__}",
                'method': request.method,
                'user': str(request.user),
                'path': request.path,
            }

            # Console output (for immediate visibility)
            print("\n" + "="*80)
            print(f"❌ ERROR DETECTED [ID: {error_id}]")
            print("="*80)
            print(f"Type: {type(e).__name__}")
            print(f"Message: {str(e)}")
            print("\n📍 TRACEBACK:")
            traceback.print_exc()
            print("\n🔍 ERROR CONTEXT:")
            for key, value in error_details.items():
                print(f"{key}: {value}")
            print("="*80 + "\n")

            # Logging to file
            logger.error(f"Error ID {error_id}: {str(e)}",
                extra={
                    'error_details': error_details,
                    'traceback': traceback.format_exc()
                }
            )

            # Determine response based on environment
            if settings.DEBUG:
                # Detailed error response in development
                return Response({
                    'error': 'An unexpected error occurred',
                    'error_id': error_id,
                    'details': {
                        'type': type(e).__name__,
                        'message': str(e),
                        'traceback': traceback.format_exc().split('\n')
                    }
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            else:
                # Generic error response in production
                return Response({
                    'error': 'An unexpected error occurred',
                    'error_id': error_id,
                    'message': 'Please contact support with this error ID'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return wrapper
