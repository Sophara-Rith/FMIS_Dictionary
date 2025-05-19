# users/views.py
from datetime import datetime, timedelta
import logging
import traceback
import base64
import binascii
from venv import logger
from zoneinfo import ZoneInfo
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenBlacklistView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models import F, Q
from django.conf import settings
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from debug_utils import debug_error
from .models import MobileDevice, User, UserComment
from .serializers import UserCommentSerializer, UserCommentSubmitSerializer, UserSerializer, PasswordValidator
from .utils import *
from users import serializers

User = get_user_model()

logger = logging.getLogger(__name__)

class UserLoginView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="User Login Endpoint",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['login_input', 'password'],
            properties={
                'login_input': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Encrypted Username or Email"
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Encrypted User password"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Successful Login',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                                'access': openapi.Schema(type=openapi.TYPE_STRING),
                                'user': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'username': openapi.Schema(type=openapi.TYPE_STRING),
                                        'username_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                                        'staff_id': openapi.Schema(type=openapi.TYPE_STRING),
                                        'position': openapi.Schema(type=openapi.TYPE_STRING),
                                        'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                                        'role': openapi.Schema(type=openapi.TYPE_STRING)
                                    }
                                )
                            }
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request):
        try:
            # Extract encrypted login credentials
            encrypted_login_input = request.data.get('login_input', '').strip()
            encrypted_password = request.data.get('password', '').strip()

            # Validate input fields
            if not encrypted_login_input or not encrypted_password:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Username/Email and password are required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Decrypt login input and password
            try:
                login_input = self.decrypt_data(encrypted_login_input)
                password = self.decrypt_data(encrypted_password)
            except Exception as e:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': f'Invalid encrypted data format: {str(e)}',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Attempt to authenticate user
            user = None
            if '@' in login_input:
                user = User.objects.filter(email=login_input).first()
            else:
                user = User.objects.filter(username=login_input).first()

            if user and user.is_suspended:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'Your account has been suspended',
                    'data': {
                        'suspended_at': user.suspended_at,
                        'reason': user.suspension_reason
                    }
                }, status=status.HTTP_403_FORBIDDEN)

            # Validate user and password
            if user and user.check_password(password):
                # Update user login information
                # Check which fields exist in the model before updating
                update_fields = ['last_login']

                user.last_login = timezone.now()

                # Check if last_login_attempt field exists
                if hasattr(user, 'last_login_attempt'):
                    user.last_login_attempt = timezone.now()
                    update_fields.append('last_login_attempt')

                # Check if login_attempt field exists
                if hasattr(user, 'login_attempt'):
                    user.login_attempt = F('login_attempt') + 1
                    update_fields.append('login_attempt')

                # Save only the fields that exist
                user.save(update_fields=update_fields)

                # Generate tokens
                refresh = RefreshToken.for_user(user)

                # Log the successful login
                log_activity(
                    admin_user=user,
                    action='USER_LOGIN',
                    target_user=user
                )

                # Prepare user data for response
                user_data = {
                    'id': user.id,
                    'username': user.username,
                    'username_kh': getattr(user, 'username_kh', ''),
                    'email': user.email,
                    'staff_id': getattr(user, 'staff_id', ''),
                    'position': getattr(user, 'position', ''),
                    'phone_number': getattr(user, 'phone_number', ''),
                    'role': getattr(user, 'role', '')
                }

                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'message': 'Login successful',
                    'data': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'user': user_data
                    }
                }, status=status.HTTP_200_OK)
            else:
                # Invalid credentials
                if user:
                    # Check which fields exist before updating
                    update_fields = []

                    if hasattr(user, 'last_login_attempt'):
                        user.last_login_attempt = timezone.now()
                        update_fields.append('last_login_attempt')

                    # Only save if there are fields to update
                    if update_fields:
                        user.save(update_fields=update_fields)

                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'message': 'Invalid login credentials',
                    'data': None
                }, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            # Comprehensive error logging
            logger.error(f"Login Error: {str(e)}")
            logger.error(f"Error Details: {traceback.format_exc()}")
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'An unexpected error occurred during login',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def decrypt_data(self, encrypted_data):
        """
        Decrypt OpenSSL-compatible AES-256 encrypted data
        Format: "Salted__" + 8 bytes salt + ciphertext
        """
        try:
            # Get current year and month
            current_year = datetime.now().strftime('%Y')  # Format: YYYY
            current_month = datetime.now().strftime('%m')  # Format: MM

            # Fixed template with placeholders
            key_template = "Ajv!ndfjkhg0${current_year}g0sno%eu$rtg@nejog${current_month}"

            # Replace placeholders with actual values
            dynamic_key = key_template.replace("${current_year}", current_year).replace("${current_month}", current_month)

            # First, try to decode from base64
            try:
                # Decode the base64 encrypted data
                encrypted_bytes = base64.b64decode(encrypted_data)
            except binascii.Error:
                # If standard base64 fails, try URL-safe base64
                encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)

            logger.debug(f"Decoded bytes length: {len(encrypted_bytes)}")

            # Check if it's in OpenSSL format (starts with "Salted__")
            if len(encrypted_bytes) < 16 or encrypted_bytes[:8] != b'Salted__':
                logger.error("Not in OpenSSL format (missing 'Salted__' prefix)")

                # Try to handle the case where the data might be double-encoded or formatted differently
                if encrypted_data.startswith("U2FsdGVk"):  # Base64 of "Salted"
                    logger.debug("Trying to handle double-encoded data")
                    # Try to decode one more time
                    try:
                        encrypted_bytes = base64.b64decode(encrypted_data)
                    except:
                        pass

                # If still not in the right format, raise error
                if len(encrypted_bytes) < 16 or encrypted_bytes[:8] != b'Salted__':
                    raise ValueError("Invalid encrypted format - not OpenSSL compatible")

            # Extract salt (next 8 bytes after "Salted__")
            salt = encrypted_bytes[8:16]
            logger.debug(f"Salt (hex): {salt.hex()}")

            # Extract ciphertext (everything after salt)
            ciphertext = encrypted_bytes[16:]
            logger.debug(f"Ciphertext length: {len(ciphertext)}")

            # Derive key and IV using OpenSSL's EVP_BytesToKey
            # This is equivalent to OpenSSL's EVP_BytesToKey with MD5, one iteration
            # We need 48 bytes (32 for key, 16 for IV)
            key_iv = self._openssl_kdf(dynamic_key.encode(), salt, 48)
            key = key_iv[:32]  # First 32 bytes for the key
            iv = key_iv[32:48]  # Next 16 bytes for the IV

            # Create AES cipher in CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Decrypt and unpad
            try:
                decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                # Return as string
                result = decrypted_data.decode('utf-8')
                return result
            except ValueError as e:
                logger.error(f"Padding error: {str(e)}")
                # Try without unpadding (in case the frontend didn't pad properly)
                decrypted_data = cipher.decrypt(ciphertext)
                result = decrypted_data.decode('utf-8', errors='ignore').rstrip('\0')
                return result

        except (ValueError, binascii.Error, UnicodeDecodeError) as e:
            logger.error(f"OpenSSL decryption error: {str(e)}")
            raise ValueError(f"Invalid encrypted data format: {str(e)}")

    def _openssl_kdf(self, password, salt, key_length):
        """
        Derive key using OpenSSL's EVP_BytesToKey with MD5, one iteration.
        This is not the PBKDF2 that we typically recommend for new applications,
        but this matches the default OpenSSL behavior.
        """
        from hashlib import md5

        result = b''
        prev = b''

        # Keep generating key material until we have enough
        while len(result) < key_length:
            prev = md5(prev + password + salt).digest()
            result += prev

        # Return the desired key length
        return result[:key_length]

class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="View list of users with pagination",
        manual_parameters=[
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number",
                type=openapi.TYPE_INTEGER,
                default=1
            ),
            openapi.Parameter(
                'per_page',
                openapi.IN_QUERY,
                description="Users per page",
                type=openapi.TYPE_INTEGER,
                default=25
            ),
            openapi.Parameter(
                'role',
                openapi.IN_QUERY,
                description="Filter by user role",
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'is_active',
                openapi.IN_QUERY,
                description="Filter by active status (true/false)",
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'is_suspended',
                openapi.IN_QUERY,
                description="Filter by suspension status (true/false)",
                type=openapi.TYPE_STRING,
                required=False
            )
        ],
        responses={
            200: openapi.Response(
                description='Users retrieved successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'users': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(
                                        type=openapi.TYPE_OBJECT,
                                        properties={
                                            'id': openapi.Schema(type=openapi.TYPE_STRING),
                                            'staff_id': openapi.Schema(type=openapi.TYPE_STRING),
                                            'username_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'sex': openapi.Schema(type=openapi.TYPE_STRING),
                                            'position': openapi.Schema(type=openapi.TYPE_STRING),
                                            'email': openapi.Schema(type=openapi.TYPE_STRING),
                                            'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                                            'date_joined': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                                            'role': openapi.Schema(type=openapi.TYPE_STRING),
                                            'is_suspended': openapi.Schema(type=openapi.TYPE_INTEGER, description='0: Not Suspended, 1: Suspended')
                                        }
                                    )
                                ),
                                'pagination': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'total_users': openapi.Schema(type=openapi.TYPE_INTEGER),
                                        'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                        'per_page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                        'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER)
                                    }
                                )
                            }
                        )
                    }
                )
            ),
            401: openapi.Response(
                description='Unauthorized Access',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            )
        }
    )
    @debug_error
    def get(self, request):
        # Explicit check for authentication
        if not request.user or not request.user.is_authenticated:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Authentication credentials were not provided or are invalid',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check for admin/superuser permissions
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'You do not have permission to perform this action',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            # Get pagination parameters
            try:
                page = max(1, int(request.query_params.get('page', 1)))
                per_page = max(1, int(request.query_params.get('per_page', 50)))
            except ValueError:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid pagination parameters',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Optional filtering parameters
            role = request.query_params.get('role')
            is_active = request.query_params.get('is_active')
            is_suspended = request.query_params.get('is_suspended')

            # Base queryset with soft delete filter
            users = User.objects.filter(is_deleted=False)

            if request.user.role == 'ADMIN':
                # ADMIN users cannot see SUPERUSER accounts or MOBILE accounts
                users = users.exclude(role='SUPERUSER').exclude(role='MOBILE')

            # Apply additional filters if provided
            if role:
                users = users.filter(role=role)

            if is_active is not None:
                users = users.filter(is_active=is_active.lower() == 'true')

            if is_suspended is not None:
                users = users.filter(is_suspended=is_suspended.lower() == 'true')

            # Calculate pagination values
            total_users = users.count()
            total_pages = (total_users + per_page - 1) // per_page

            # Apply pagination
            start = (page - 1) * per_page
            end = start + per_page
            paginated_users = users[start:end]

            # Transform data
            user_data = [{
                'id': user.id,
                'staff_id': convert_to_khmer_number(user.staff_id) if user.staff_id else '',
                'username_kh': user.username_kh or '',
                'sex': user.sex or '',
                'position': user.position or '',
                'email': user.email,
                'phone_number': convert_to_khmer_number(user.phone_number) if user.phone_number else '',
                'date_joined': convert_to_khmer_date(user.date_joined.strftime('%d-%m-%Y')) if user.date_joined else '',
                'role': user.role,
                'is_suspended': 1 if user.is_suspended else 0,
                'suspended_reason': user.suspension_reason or '',
                'suspended_at': user.suspended_at.isoformat() if user.suspended_at else ''
            } for user in paginated_users]

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Users retrieved successfully',
                'data': {
                    'users': user_data,
                    'total_entries': total_users,
                    'current_page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': f'Failed to retrieve users: {str(e)}',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve user details",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="User ID",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'username',
                openapi.IN_QUERY,
                description="Username",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'email',
                openapi.IN_QUERY,
                description="User Email",
                type=openapi.TYPE_STRING
            )
        ],
        responses={
            200: openapi.Response(
                description='User profile retrieved successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'username': openapi.Schema(type=openapi.TYPE_STRING),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'role': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def get(self, request):
        user_id = request.query_params.get('id')
        username = request.query_params.get('username')
        email = request.query_params.get('email')

        try:
            # Find user based on provided parameters
            if user_id:
                user = get_object_or_404(User, id=user_id)
            elif username:
                user = get_object_or_404(User, username=username)
            elif email:
                user = get_object_or_404(User, email=email)
            else:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Identification parameter (id/username/email) is required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Ensure user can only access their own profile or admin can access all
            if request.user.id != user.id and request.user.role not in ['ADMIN', 'SUPERUSER']:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'Not authorized to view this user profile',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Transform user data to match desired structure
            user_data = {
                'id': user.id,
                'staff_id': convert_to_khmer_number(user.staff_id) if user.staff_id else '',
                'username': user.username or '',
                'username_kh': user.username_kh or '',
                'sex': user.sex or '',
                'position': user.position or '',
                'email': user.email,
                'phone_number': convert_to_khmer_number(user.phone_number) if user.phone_number else '',
                'date_joined': convert_to_khmer_date(user.date_joined.strftime('%d-%m-%Y')) if user.date_joined else '',
                'role': user.role,
                'is_suspended': 1 if user.is_suspended else 0,
                'suspended_reason': user.suspension_reason,
                'suspended_at': user.suspended_at
            }

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'User profile retrieved successfully',
                'data': user_data
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': str(e),
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

class UserRegisterView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="User Registration",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['email', 'password', 'role'],
            properties={
                'email': openapi.Schema(type=openapi.TYPE_STRING, description="Encrypted email"),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description="Encrypted password"),
                'role': openapi.Schema(type=openapi.TYPE_STRING, description="Encrypted role"),
                'sex': openapi.Schema(type=openapi.TYPE_STRING, description="Encrypted sex"),
                'username_kh': openapi.Schema(type=openapi.TYPE_STRING, description="Encrypted Khmer username"),
                'staff_id': openapi.Schema(type=openapi.TYPE_STRING, description="Encrypted staff ID"),
                'position': openapi.Schema(type=openapi.TYPE_STRING, description="Encrypted position"),
                'phone_number': openapi.Schema(type=openapi.TYPE_STRING, description="Encrypted phone number")
            }
        ),
        responses={
            201: openapi.Response(
                description='User Created Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'username': openapi.Schema(type=openapi.TYPE_STRING),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'role': openapi.Schema(type=openapi.TYPE_STRING),
                                'sex': openapi.Schema(type=openapi.TYPE_STRING),
                                'username_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                'staff_id': openapi.Schema(type=openapi.TYPE_STRING),
                                'position': openapi.Schema(type=openapi.TYPE_STRING),
                                'phone_number': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request):
        # Check authentication and authorization
        if not request.user or not request.user.is_authenticated:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Authentication required',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check authorization to create users
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'You do not have permission to register users',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            # Create a dictionary to hold decrypted data
            decrypted_data = {}

            # Decrypt each field in the request data
            for field, value in request.data.items():
                if value and isinstance(value, str):
                    try:
                        decrypted_value = self.decrypt_data(value)
                        decrypted_data[field] = decrypted_value
                        logger.debug(f"Decrypted {field}: {decrypted_value}")
                    except Exception as e:
                        logger.error(f"Failed to decrypt {field}: {str(e)}")
                        # If decryption fails, use the original value
                        decrypted_data[field] = value
                else:
                    # For non-string or empty values, use as is
                    decrypted_data[field] = value

            # Validate role creation permissions
            requested_role = decrypted_data.get('role', 'USER')
            if request.user.role == 'ADMIN' and requested_role in ['SUPERUSER']:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'ADMIN cannot create SUPERUSER accounts',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Validate email domain and extract username
            email = decrypted_data.get('email', '')
            if not email or not email.endswith('@fmis.gov.kh'):
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid email. Must be a FMIS email address',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Extract username from email
            username = email.split('@')[0]

            # Add username to decrypted data
            decrypted_data['username'] = username

            # Validate and create user
            serializer = UserSerializer(data=decrypted_data)

            if serializer.is_valid():
                new_user = serializer.save()

                # Log the user creation
                log_activity(
                    admin_user=request.user,
                    action='USER_CREATE',
                    target_user=new_user
                )

                # Prepare response data
                response_data = {
                    'username': new_user.username,
                    'email': new_user.email,
                    'role': new_user.role,
                    'sex': getattr(new_user, 'sex', ''),
                    'username_kh': getattr(new_user, 'username_kh', ''),
                    'staff_id': getattr(new_user, 'staff_id', ''),
                    'position': getattr(new_user, 'position', ''),
                    'phone_number': getattr(new_user, 'phone_number', '')
                }

                return Response({
                    'responseCode': status.HTTP_201_CREATED,
                    'message': 'User registered successfully',
                    'data': response_data
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Validation error',
                    'data': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"User registration error: {str(e)}")
            logger.error(f"Error details: {traceback.format_exc()}")
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': f'Registration failed: {str(e)}',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def decrypt_data(self, encrypted_data):
        """
        Decrypt OpenSSL-compatible AES-256 encrypted data
        Format: "Salted__" + 8 bytes salt + ciphertext
        """
        try:
            # Get current year and month
            current_year = datetime.now().strftime('%Y')  # Format: YYYY
            current_month = datetime.now().strftime('%m')  # Format: MM

            # Fixed template with placeholders
            key_template = "Ajv!ndfjkhg0${current_year}g0sno%eu$rtg@nejog${current_month}"

            # Replace placeholders with actual values
            dynamic_key = key_template.replace("${current_year}", current_year).replace("${current_month}", current_month)

            # Decode the base64 encrypted data
            try:
                # Decode the base64 encrypted data
                encrypted_bytes = base64.b64decode(encrypted_data)
            except binascii.Error:
                # If standard base64 fails, try URL-safe base64
                encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)

            # Check if it's in OpenSSL format (starts with "Salted__")
            if len(encrypted_bytes) < 16 or encrypted_bytes[:8] != b'Salted__':
                logger.error("Not in OpenSSL format (missing 'Salted__' prefix)")
                raise ValueError("Invalid encrypted format - not OpenSSL compatible")

            # Extract salt (next 8 bytes after "Salted__")
            salt = encrypted_bytes[8:16]

            # Extract ciphertext (everything after salt)
            ciphertext = encrypted_bytes[16:]

            # Derive key and IV using OpenSSL's EVP_BytesToKey
            # This is equivalent to OpenSSL's EVP_BytesToKey with MD5, one iteration
            # We need 48 bytes (32 for key, 16 for IV)
            key_iv = self._openssl_kdf(dynamic_key.encode(), salt, 48)
            key = key_iv[:32]  # First 32 bytes for the key
            iv = key_iv[32:48]  # Next 16 bytes for the IV

            # Create AES cipher in CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Decrypt and unpad
            try:
                decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                # Return as string
                return decrypted_data.decode('utf-8')
            except ValueError as e:
                logger.error(f"Padding error: {str(e)}")
                # Try without unpadding (in case the frontend didn't pad properly)
                decrypted_data = cipher.decrypt(ciphertext)
                return decrypted_data.decode('utf-8', errors='ignore').rstrip('\0')

        except (ValueError, binascii.Error, UnicodeDecodeError) as e:
            logger.error(f"OpenSSL decryption error: {str(e)}")
            raise ValueError(f"Invalid encrypted data format: {str(e)}")

    def _openssl_kdf(self, password, salt, key_length):
        """
        Derive key using OpenSSL's EVP_BytesToKey with MD5, one iteration.
        This is not the PBKDF2 that we typically recommend for new applications,
        but this matches the default OpenSSL behavior.
        """
        from hashlib import md5

        result = b''
        prev = b''

        # Keep generating key material until we have enough
        while len(result) < key_length:
            prev = md5(prev + password + salt).digest()
            result += prev

        # Return the desired key length
        return result[:key_length]

class UserDropView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete User Account",
        manual_parameters=[
            openapi.Parameter('id', openapi.IN_QUERY, type=openapi.TYPE_INTEGER),
            openapi.Parameter('username', openapi.IN_QUERY, type=openapi.TYPE_STRING),
            openapi.Parameter('email', openapi.IN_QUERY, type=openapi.TYPE_STRING)
        ],
        responses={
            200: openapi.Response(
                description='User Deleted Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            400: 'Bad Request - Missing identification parameter',
            403: 'Forbidden - Insufficient permissions',
            404: 'Not Found - User not found',
            500: 'Internal Server Error'
        }
    )
    @debug_error
    def delete(self, request):
        # Check if user is ADMIN or SUPERUSER
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'You do not have permission to delete users',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        # Get identification parameters
        user_id = request.query_params.get('id')
        username = request.query_params.get('username')
        email = request.query_params.get('email')

        # Validate at least one identification parameter is provided
        if not any([user_id, username, email]):
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'At least one identification parameter (id, username, email) is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find the user to delete
            user_query = {}
            if user_id:
                user_query['id'] = user_id
            elif username:
                user_query['username'] = username
            elif email:
                user_query['email'] = email

            # Get the user model
            User = get_user_model()

            target_user = User.objects.get(id=user_id)

            # Try to get the user, including those that might be soft-deleted
            # This is important - we need to check the base queryset, not the filtered one
            try:
                # Use the base manager to get all users including soft-deleted ones
                if hasattr(User, 'objects') and hasattr(User.objects, 'get_queryset'):
                    base_queryset = User.objects.get_queryset().filter(is_deleted=False)
                    user = base_queryset.get(**user_query)
                else:
                    # Fallback to regular manager
                    user = User.objects.get(**user_query)
            except User.DoesNotExist:
                return Response({
                    'responseCode': status.HTTP_404_NOT_FOUND,
                    'message': 'No User matches the given query.',
                    'data': None
                }, status=status.HTTP_404_NOT_FOUND)

            # Prevent deleting the current user
            if user.id == request.user.id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'You cannot delete your own account',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prevent ADMIN from deleting SUPERUSER
            if request.user.role == 'ADMIN' and user.role == 'SUPERUSER':
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'ADMIN cannot delete SUPERUSER accounts',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Store user details for response
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }

            # Perform soft delete
            user.soft_delete()

            # Log the user creation activity
            log_activity(
                admin_user=request.user,
                action='USER_DELETE',
                target_user=target_user
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'User deleted successfully',
                'data': user_data
            })

        except Exception as e:
            # Log the error for debugging
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error deleting user: {str(e)}", exc_info=True)

            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': f'Deletion failed: {str(e)}',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="""
        Update User Profile (Partial Update)
            Access Levels:

            |- USER:
            |* Can only update own password
            |* Cannot specify user ID
            |-----------------------------------
            |*** Endpoint: /users/update

            |- ADMIN/SUPERUSER:
            |* Can update any user's profile
            |* Can specify user ID to update
            |* Can modify all fields
            |-----------------------------------
            |*** Endpoint: /users/update?id={id}
        """,
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="User ID to update (Admin Only)",
                type=openapi.TYPE_INTEGER
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="New password (All users)",
                    format='password'
                ),
                # Admin-only fields
                'username': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Username (Admin Only)"
                ),
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Email address (Admin Only)"
                ),
                'role': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User role (Admin Only)",
                    enum=['USER', 'ADMIN', 'SUPERUSER']
                ),
                'sex': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User sex (Admin Only)",
                    enum=['MALE', 'FEMALE', 'OTHER']
                ),
                'username_kh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Khmer username (Admin Only)"
                ),
                'staff_id': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Staff ID (Admin Only)"
                ),
                'position': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Job position (Admin Only)"
                ),
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Phone number (Admin Only)"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='User Updated Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=200
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Update status message',
                            example='User updated successfully'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'username': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Updated username'
                                ),
                                'email': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Updated email'
                                ),
                                'role': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='User role'
                                ),
                                'sex': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='User sex'
                                ),
                                'username_kh': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Khmer username'
                                ),
                                'staff_id': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Staff ID'
                                ),
                                'position': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Job position'
                                ),
                                'phone_number': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Phone number'
                                )
                            }
                        )
                    }
                )
            ),
            400: openapi.Response(
                description='Validation Error',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            example=400
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='Validation error'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            description='Validation error details'
                        )
                    }
                )
            ),
            403: openapi.Response(
                description='Forbidden',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            example=403
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            example='You are not authorized to update other fields'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            nullable=True
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def patch(self, request):
        try:
            # Determine which user to update
            user_id = request.query_params.get('id')

            # Regular users can only update themselves
            if request.user.role not in ['ADMIN', 'SUPERUSER']:
                # If user tries to specify an ID, deny the request
                if user_id:
                    return Response({
                        'responseCode': status.HTTP_403_FORBIDDEN,
                        'message': 'You are not authorized to update other user profiles',
                        'data': None
                    }, status=status.HTTP_403_FORBIDDEN)
                # Set user to current authenticated user
                user = request.user
            # Admins can update other users
            else:
                # If no ID provided, update current user
                if not user_id:
                    user = request.user
                else:
                    # Find user by ID
                    try:
                        user = User.objects.get(id=user_id)
                    except User.DoesNotExist:
                        return Response({
                            'responseCode': status.HTTP_404_NOT_FOUND,
                            'message': 'User not found',
                            'data': None
                        }, status=status.HTTP_404_NOT_FOUND)

            # Prepare update data
            update_data = {}

            # Regular users can only update password
            if request.user.role not in ['ADMIN', 'SUPERUSER']:
                if 'password' in request.data:
                    # Only add password to update_data if it's different from the current password
                    if not user.check_password(request.data['password']):
                        update_data['password'] = request.data['password']
                    else:
                        return Response({
                            'responseCode': status.HTTP_400_BAD_REQUEST,
                            'message': 'New password must be different from the current password',
                            'data': None
                        }, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({
                        'responseCode': status.HTTP_403_FORBIDDEN,
                        'message': 'You are only authorized to update your password',
                        'data': None
                    }, status=status.HTTP_403_FORBIDDEN)

            # Admins can update all fields
            else:
                # List of fields admins can update
                allowed_admin_fields = [
                    'username', 'email', 'password', 'role',
                    'sex', 'username_kh', 'staff_id',
                    'position', 'phone_number'
                ]

                # Collect update data, only if the value is different from the current value
                for field in allowed_admin_fields:
                    if field in request.data:
                        current_value = getattr(user, field, None)

                        # Special handling for password
                        if field == 'password':
                            if not user.check_password(request.data[field]):
                                update_data[field] = request.data[field]
                        # For other fields, compare directly
                        elif str(request.data[field]) != str(current_value or ''):
                            update_data[field] = request.data[field]

                # If no changes, return a message
                if not update_data:
                    return Response({
                        'responseCode': status.HTTP_200_OK,
                        'message': 'No changes detected',
                        'data': None
                    }, status=status.HTTP_200_OK)

            # Validate and save updates
            serializer = UserSerializer(
                user,
                data=update_data,
                partial=True,
                context={'request': request}
            )

            if serializer.is_valid():
                updated_user = serializer.save()

                # Log the activity
                log_activity(
                    admin_user=request.user,
                    action='USER_UPDATE',
                    target_user=updated_user
                )

                # Prepare response data
                response_data = {
                    'username': updated_user.username,
                    'email': updated_user.email,
                    'role': updated_user.role,
                    'sex': updated_user.sex or '',
                    'username_kh': updated_user.username_kh or '',
                    'staff_id': updated_user.staff_id or '',
                    'position': updated_user.position or '',
                    'phone_number': updated_user.phone_number or ''
                }

                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'message': 'User updated successfully',
                    'data': response_data
                })

            # Handle validation errors
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Validation error',
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Update failed',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserCommentView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Submit a new comment",
        tags=['dictionary'],
        request_body=UserCommentSubmitSerializer,
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Unique identifier for the mobile device',
                required=True
            )
        ],
        responses={
            201: openapi.Response(
                description='Comment submitted successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            400: openapi.Response(
                description='Bad Request',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            )
        }
    )
    def post(self, request):
        """
        Submit a new comment from authenticated user
        """
        # Check authentication
        if not request.user or not request.user.is_authenticated:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Authentication required',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Get device_id from header
        device_id = request.headers.get('X-Device-ID')
        if not device_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'X-Device-ID header is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create data with device_id from header
            data = request.data.copy()
            data['device_id'] = device_id

            serializer = UserCommentSubmitSerializer(data=data, context={'request': request})

            if serializer.is_valid():
                comment = serializer.save()

                return Response({
                    'responseCode': status.HTTP_201_CREATED,
                    'message': 'Comment submitted successfully',
                    'data': None
                }, status=status.HTTP_201_CREATED)

            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Validation error',
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to submit comment',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Get user comments (Admin/Superuser only)",
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, default=1),
            openapi.Parameter('per_page', openapi.IN_QUERY, type=openapi.TYPE_INTEGER, default=10),
            openapi.Parameter('is_reviewed', openapi.IN_QUERY, type=openapi.TYPE_BOOLEAN)
        ],
        responses={
            200: openapi.Response(
                description='Comments retrieved successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT),
                        'total_comments': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'per_page': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER)
                    }
                )
            )
        }
    )
    def get(self, request):
        """
        Get comments with pagination and filtering (Admin/Superuser only)
        """
        # Check authentication
        if not request.user or not request.user.is_authenticated:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Authentication required',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check authorization - only ADMIN and SUPERUSER can access
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'Access denied. Requires admin privileges.',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            # Pagination parameters
            page = int(request.query_params.get('page', 1))
            per_page = int(request.query_params.get('per_page', 10))
            is_reviewed = request.query_params.get('is_reviewed')

            # Base queryset - all comments for admin/superuser
            comments = UserComment.objects.select_related('user').all().order_by('-created_at')

            # Apply filters
            if is_reviewed is not None:
                comments = comments.filter(is_reviewed=is_reviewed.lower() == 'true')

            # Count total before pagination
            total_comments = comments.count()

            # Apply pagination
            start = (page - 1) * per_page
            end = start + per_page
            paginated_comments = comments[start:end]

            # Serialize data
            serializer = UserCommentSerializer(paginated_comments, many=True)

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Comments retrieved successfully',
                'data': {
                    'comments': serializer.data
                },
                'total_entries': total_comments,
                'page': page,
                'per_page': per_page,
                'total_pages': (total_comments + per_page - 1) // per_page
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to retrieve comments',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserSuspendView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Suspend a User Account",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="ID of the user to be suspended",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['reason'],
            properties={
                'reason': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Reason for suspending the user account"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='User Suspended Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'username': openapi.Schema(type=openapi.TYPE_STRING),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'suspended_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                                'suspended_reason': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            ),
            400: openapi.Response(
                description='Bad Request - Validation Error',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            ),
            403: openapi.Response(
                description='Forbidden - Insufficient Permissions',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request):
        # Check user permissions
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'You do not have permission to suspend users',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        # Get user ID from query parameter
        user_id = request.query_params.get('id')
        if not user_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'User ID is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate reason
        reason = request.data.get('reason')
        if not reason:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Suspension reason is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find the user
            user = User.objects.get(id=user_id)

            # Check if user is already suspended
            if user.is_suspended:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'User is already suspended',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Suspend the user
            user.is_suspended = True
            user.suspended_at = timezone.now()
            user.suspension_reason = reason
            user.suspended_by = request.user
            user.save(update_fields=['is_suspended', 'suspended_at', 'suspension_reason', 'suspended_by'])

            # Log the suspension activity
            log_activity(
                admin_user=request.user,
                action='USER_SUSPENDED',
                target_user=user
                # details=f"Reason: {reason}"
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'User suspended successfully',
                'data': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'suspended_at': user.suspended_at.isoformat(),
                    'suspended_reason': user.suspension_reason
                }
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'User not found',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': f'An error occurred: {str(e)}',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserUnsuspendView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Unsuspend a User Account",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="ID of the user to be unsuspended",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'reason': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Optional reason for unsuspending the user account"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='User Unsuspended Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'username': openapi.Schema(type=openapi.TYPE_STRING),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'unsuspended_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time')
                            }
                        )
                    }
                )
            ),
            400: openapi.Response(
                description='Bad Request - Validation Error',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            ),
            403: openapi.Response(
                description='Forbidden - Insufficient Permissions',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request):
        # Check user permissions
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'You do not have permission to unsuspend users',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        # Get user ID from query parameter
        user_id = request.query_params.get('id')
        if not user_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'User ID is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        # Optional reason for unsuspension
        reason = request.data.get('reason', 'Administrative action')

        try:
            # Find the user
            user = User.objects.get(id=user_id)

            # Check if user is already active
            if not user.is_suspended:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'User is not currently suspended',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Unsuspend the user
            user.is_suspended = False
            user.suspended_at = None
            user.suspension_reason = None
            user.unsuspended_by = request.user
            user.unsuspended_at = timezone.now()
            user.save(update_fields=[
                'is_suspended',
                'suspended_at',
                'suspension_reason',
                'unsuspended_by',
                'unsuspended_at'
            ])

            # Log the unsuspension activity
            log_activity(
                admin_user=request.user,
                action='USER_UNSUSPENDED',
                target_user=user
                # action_details=f"Reason: {reason}"
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'User unsuspended successfully',
                'data': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'unsuspended_at': user.unsuspended_at.isoformat()
                }
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'User not found',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': f'An error occurred: {str(e)}',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CustomTokenObtainPairView(TokenObtainPairView):
    @swagger_auto_schema(
        operation_description="Obtain JWT Tokens with Flexible Login",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['login_input', 'password'],
            properties={
                'login_input': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Username or Email for login",
                    example="johndoe or johndoe@example.com"
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User password",
                    format='password'
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Token Generated Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=200
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Token generation status message',
                            example='Token generated successfully'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'refresh': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='JWT Refresh Token'
                                ),
                                'access': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='JWT Access Token'
                                ),
                                'login_method': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Method used for login (username/email)',
                                    example='email'
                                )
                            }
                        )
                    }
                )
            ),
            400: openapi.Response(
                description='Bad Request - Invalid Credentials',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=400
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Error message',
                            example='Invalid login credentials'
                        ),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            ),
            401: openapi.Response(
                description='Unauthorized - Authentication Failed',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=401
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Authentication failure message',
                            example='Token generation failed'
                        ),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request, *args, **kwargs):
        try:
            # Override the request data to use login_input
            login_input = request.data.get('login_input')
            password = request.data.get('password')

            # Modify request data to match TokenObtainPairSerializer
            request.data['username'] = login_input

            # Call parent method
            response = super().post(request, *args, **kwargs)

            # Enhance response with login method
            response_data = response.data.copy()

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Token generated successfully',
                'data': {
                    **response_data
                }
            })

        except Exception as e:
            # Log the exception for debugging
            logger.error(f"Token generation error: {str(e)}")

            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Token generation failed',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

class CustomTokenRefreshView(TokenRefreshView):
    @swagger_auto_schema(
        operation_description="Refresh JWT Token",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['refresh'],
            properties={
                'refresh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Current refresh token',
                    example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Token Refreshed Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=200
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Token refresh status message',
                            example='Token refreshed successfully'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'refresh': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='New JWT Refresh Token'
                                ),
                                'access': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='New JWT Access Token'
                                )
                            }
                        )
                    }
                )
            ),
            401: openapi.Response(
                description='Token Refresh Failed',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=401
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Token refresh error message',
                            example='Token refresh failed'
                        ),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request, *args, **kwargs):
        try:
            # Call parent method to get new tokens
            response = super().post(request, *args, **kwargs)

            # Log the raw response data for debugging
            logger.info(f"Raw Token Refresh Response: {response.data}")

            # Ensure both tokens are present
            refresh_token = response.data.get('refresh')
            access_token = response.data.get('access')

            if not refresh_token:
                logger.warning("Refresh token is missing during token refresh")

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Token refreshed successfully',
                'data': {
                    'refresh': refresh_token,  # This might be None
                    'access': access_token
                }
            })

        except Exception as e:
            # Log the exception for comprehensive debugging
            logger.error(f"Token refresh error: {str(e)}")

            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Token refresh failed',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

class CustomTokenBlacklistView(TokenBlacklistView):
    @swagger_auto_schema(
        operation_description="Blacklist JWT Refresh Token",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['refresh'],
            properties={
                'refresh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Refresh token to be blacklisted',
                    example='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Token Blacklisted Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=200
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Token blacklist status message',
                            example='Token blacklisted successfully'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            nullable=True,
                            description='Additional data (null in this case)'
                        )
                    }
                )
            ),
            400: openapi.Response(
                description='Token Blacklist Failed',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=400
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Token blacklist error message',
                            example='Token blacklist failed'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            nullable=True
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request, *args, **kwargs):
        try:
            # Validate refresh token is present
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Refresh token is required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Attempt to blacklist the token
            try:
                # Call parent method to blacklist token
                response = super().post(request, *args, **kwargs)

                # Log successful blacklist (optional)
                logger.info(f"Token successfully blacklisted: {refresh_token[:10]}...")

                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'message': 'Token blacklisted successfully',
                    'data': None
                })

            except TokenError as token_error:
                # Handle specific token-related errors
                logger.error(f"Token blacklist error: {str(token_error)}")
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid or already blacklisted token',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Catch and log any unexpected errors
            logger.error(f"Unexpected token blacklist error: {str(e)}")
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Token blacklist failed',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MobileLoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Mobile User Login Endpoint",
        tags=['mobile'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['login_input', 'password'],
            properties={
                'login_input': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's username or email",
                    example="fmis369.dic"
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's password",
                    format='password'
                ),
                'device_id': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Unique device identifier for mobile device",
                    example="abc123xyz456"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Successful Login',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=200
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Login success message',
                            example='Login successful'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'access_token': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='JWT access token'
                                ),
                                'refresh_token': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='JWT refresh token'
                                ),
                                'user': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                        'username': openapi.Schema(type=openapi.TYPE_STRING),
                                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                                        'role': openapi.Schema(type=openapi.TYPE_STRING)
                                    }
                                )
                            }
                        )
                    }
                )
            ),
            400: openapi.Response(
                description='Bad Request - Invalid Credentials',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=400
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Error message',
                            example='Invalid username or password'
                        ),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            ),
            429: openapi.Response(
                description='Too Many Requests',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='HTTP status code',
                            example=429
                        ),
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Rate limit error',
                            example='Too many login attempts. Please try again later.'
                        ),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True)
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request):
        # Extract parameters
        device_id = request.data.get('device_id')
        login_input = request.data.get('login_input')
        encrypted_password = request.data.get('password')
        device_name = request.data.get('device_name', '')
        device_type = request.data.get('device_type', '')

        # Validate required parameters
        if not all([device_id, login_input, encrypted_password]):
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Missing required parameters',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # OpenSSL-compatible AES-256 encryption in CBC mode
            # Decrypt the device_id if it's encrypted
            try:
                # Check if device_id looks like base64 (potential encryption)
                import re
                if re.match(r'^[A-Za-z0-9+/]+={0,2}$', login_input):
                    try:
                        # Try to decrypt it
                        login_input = self.decrypt_data(login_input)
                        logger.info(f"Successfully decrypted login_input: {login_input}")
                    except Exception as e:
                        # If decryption fails, use as-is
                        logger.warning(f"Device ID decryption failed, using as-is: {str(e)}")
                        login_input = login_input
                else:
                    # Not base64, use as-is
                    login_input = login_input

            except Exception as e:
                logger.error(f"Error processing login_input: {str(e)}")
                login_input = login_input  # Fallback to using as-is

            # Decrypt the device_id if it's encrypted
            try:
                # Check if device_id looks like base64 (potential encryption)
                import re
                if re.match(r'^[A-Za-z0-9+/]+={0,2}$', device_id):
                    try:
                        # Try to decrypt it
                        device_id = self.decrypt_data(device_id)
                        logger.info(f"Successfully decrypted device_id: {device_id}")
                    except Exception as e:
                        # If decryption fails, use as-is
                        logger.warning(f"Device ID decryption failed, using as-is: {str(e)}")
                        device_id = device_id
                else:
                    # Not base64, use as-is
                    device_id = device_id

            except Exception as e:
                logger.error(f"Error processing device_id: {str(e)}")
                device_id = device_id  # Fallback to using as-is

            # Decrypt the password using OpenSSL-compatible method
            try:
                password = self.decrypt_data(encrypted_password)
                logger.info("Successfully decrypted password")
            except ValueError as e:
                logger.error(f"Password decryption failed: {str(e)}")
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid encrypted password format',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Explicitly import User model
            from django.contrib.auth import get_user_model
            User = get_user_model()

            # Find user with MOBILE role
            try:
                mobile_user = User.objects.get(
                    username=login_input,
                    role='MOBILE'
                )

                # Validate password
                if not mobile_user.check_password(password):
                    raise User.DoesNotExist

            except User.DoesNotExist:
                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'message': 'Invalid mobile credentials',
                    'data': None
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Check if user is suspended
            if hasattr(mobile_user, 'is_suspended') and mobile_user.is_suspended:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'This mobile account has been suspended',
                    'data': {
                        'suspended_at': mobile_user.suspended_at,
                        'reason': mobile_user.suspension_reason
                    }
                }, status=status.HTTP_403_FORBIDDEN)

            # Generate tokens with custom method for precise control
            access_token, refresh_token, token_expires_at = self.generate_mobile_tokens(mobile_user, device_id)

            # Use UTC+7 for logging and other timestamp operations
            utc_plus_7 = ZoneInfo("Asia/Phnom_Penh")
            current_time = datetime.now(utc_plus_7)

            # Instead of deleting and creating, use update_or_create
            mobile_device, created = MobileDevice.objects.update_or_create(
                device_id=device_id,  # This is the lookup field
                defaults={  # These fields will be updated if the record exists
                    'user': mobile_user,
                    'device_name': device_name,
                    'device_type': device_type,
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'is_active': True,
                    'token_created_at': current_time,
                    'token_expires_at': token_expires_at,
                    'last_activity_at': current_time
                }
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Mobile login successful',
                'data': {
                    'refresh': refresh_token,
                    'access': access_token,
                    'device_id': device_id
                }
            })

        except Exception as e:
            # Comprehensive error logging
            logger.error(f"Mobile Login Error: {str(e)}")
            logger.error(f"Error Details: {traceback.format_exc()}")
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Mobile login failed',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            # Comprehensive error logging
            logger.error(f"Mobile Login Error: {str(e)}")
            logger.error(f"Error Details: {traceback.format_exc()}")
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Mobile login failed',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def decrypt_data(self, encrypted_password):
        """
        Decrypt OpenSSL-compatible AES-256 encrypted password
        Format: "Salted__" + 8 bytes salt + ciphertext
        """
        try:

            # Get current year and month
            current_year = datetime.now().strftime('%Y')  # Format: YYYY
            current_month = datetime.now().strftime('%m')  # Format: MM

            # Fixed template with placeholders
            key_template = "Ajv!ndfjkhg0${current_year}g0sno%eu$rtg@nejog${current_month}"

            # Replace placeholders with actual values
            dynamic_key = key_template.replace("${current_year}", current_year).replace("${current_month}", current_month)

            # Decode the base64 encrypted data
            encrypted_data = base64.b64decode(encrypted_password)

            # Check if it's in OpenSSL format (starts with "Salted__")
            if encrypted_data[:8] != b'Salted__':
                logger.error("Not in OpenSSL format (missing 'Salted__' prefix)")
                raise ValueError("Invalid encrypted format - not OpenSSL compatible")

            # Extract salt (next 8 bytes after "Salted__")
            salt = encrypted_data[8:16]

            # Extract ciphertext (everything after salt)
            ciphertext = encrypted_data[16:]

            # Derive key and IV using OpenSSL's EVP_BytesToKey
            # This is equivalent to OpenSSL's EVP_BytesToKey with MD5, one iteration
            # We need 48 bytes (32 for key, 16 for IV)
            key_iv = self._openssl_kdf(dynamic_key.encode(), salt, 48)
            key = key_iv[:32]  # First 32 bytes for the key
            iv = key_iv[32:48]  # Next 16 bytes for the IV

            # Create AES cipher in CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Decrypt and unpad
            decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)

            # Return as string
            return decrypted_data.decode('utf-8')

        except (ValueError, binascii.Error, UnicodeDecodeError) as e:
            logger.error(f"OpenSSL decryption error: {str(e)}")
            raise ValueError(f"Invalid encrypted password format: {str(e)}")

    def _openssl_kdf(self, password, salt, key_length):
        """
        Derive key using OpenSSL's EVP_BytesToKey with MD5, one iteration.
        This is not the PBKDF2 that we typically recommend for new applications,
        but this matches the default OpenSSL behavior.
        """
        from hashlib import md5

        result = b''
        prev = b''

        # Keep generating key material until we have enough
        while len(result) < key_length:
            prev = md5(prev + password + salt).digest()
            result += prev

        # Return the desired key length
        return result[:key_length]

    @staticmethod
    def generate_mobile_tokens(user, device_id):
        from rest_framework_simplejwt.tokens import RefreshToken
        from django.conf import settings
        from zoneinfo import ZoneInfo
        from datetime import datetime, timedelta

        # Use mobile-specific JWT settings
        mobile_settings = settings.MOBILE_JWT_SETTINGS

        # Create refresh token with mobile-specific lifetime
        refresh = RefreshToken.for_user(user)

        # Temporarily override token lifetimes for mobile
        original_access_lifetime = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']
        original_refresh_lifetime = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']

        try:
            # Override with mobile-specific settings
            settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'] = mobile_settings['ACCESS_TOKEN_LIFETIME']
            settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'] = mobile_settings['REFRESH_TOKEN_LIFETIME']

            # Add custom claims
            refresh['device_id'] = device_id

            # Calculate token expiration in UTC+7
            utc_plus_7 = ZoneInfo("Asia/Phnom_Penh")
            token_expires_at = datetime.now(utc_plus_7) + mobile_settings['ACCESS_TOKEN_LIFETIME']

            # Convert tokens to strings
            access_token = str(refresh.access_token)
            refresh_token = str(refresh)

            return access_token, refresh_token, token_expires_at

        finally:
            # Restore original JWT settings
            settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'] = original_access_lifetime
            settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'] = original_refresh_lifetime

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Change user password",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['current_password', 'new_password'],
            properties={
                'current_password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Current password (encrypted)"
                ),
                'new_password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="New password (encrypted)"
                ),
                'confirm_password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Confirm new password (encrypted)"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description="Password changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            400: openapi.Response(
                description="Bad request",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            )
        }
    )
    @debug_error
    def post(self, request):
        try:
            # Extract encrypted password fields
            encrypted_current_password = request.data.get('current_password', '')
            encrypted_new_password = request.data.get('new_password', '')
            encrypted_confirm_password = request.data.get('confirm_password', '')

            # Validate input fields
            if not encrypted_current_password or not encrypted_new_password:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Current password and new password are required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Decrypt password fields
            try:
                current_password = self.decrypt_data(encrypted_current_password)
                new_password = self.decrypt_data(encrypted_new_password)
                confirm_password = self.decrypt_data(encrypted_confirm_password) if encrypted_confirm_password else None

                logger.debug("Successfully decrypted password fields")
            except Exception as e:
                logger.error(f"Password decryption failed: {str(e)}")
                logger.error(f"Decryption error details: {traceback.format_exc()}")
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid encrypted password format',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate that new password and confirm password match
            if confirm_password and new_password != confirm_password:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'confirm_password New password and confirm password do not match',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get the current user
            user = request.user

            # Check if the current password is correct
            if not user.check_password(current_password):
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'current_password Current password is incorrect',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate new password complexity
            if len(new_password) < 8:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'new_password Password must be at least 8 characters long',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check for at least one lowercase letter
            if not any(c.islower() for c in new_password):
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'new_password Password must contain at least one lowercase letter',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check for at least one uppercase letter
            if not any(c.isupper() for c in new_password):
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'new_password Password must contain at least one uppercase letter',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check for at least one digit
            if not any(c.isdigit() for c in new_password):
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'new_password Password must contain at least one digit',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check for at least one special character
            if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~`' for c in new_password):
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'new_password Password must contain at least one special character',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Set the new password
            user.set_password(new_password)
            user.save()

            # Log the password change
            log_activity(
                admin_user=user,
                action='PASSWORD_CHANGE',
                target_user=user
            )

            # Return success response
            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Password changed successfully',
                'data': None
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Change password error: {str(e)}")
            logger.error(f"Error details: {traceback.format_exc()}")
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': f'An error occurred: {str(e)}',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def decrypt_data(self, encrypted_data):
        """
        Decrypt OpenSSL-compatible AES-256 encrypted data
        Format: "Salted__" + 8 bytes salt + ciphertext
        """
        try:
            # Get current year and month
            current_year = datetime.now().strftime('%Y')  # Format: YYYY
            current_month = datetime.now().strftime('%m')  # Format: MM

            # Fixed template with placeholders
            key_template = "Ajv!ndfjkhg0${current_year}g0sno%eu$rtg@nejog${current_month}"

            # Replace placeholders with actual values
            dynamic_key = key_template.replace("${current_year}", current_year).replace("${current_month}", current_month)

            # Decode the base64 encrypted data
            try:
                # Decode the base64 encrypted data
                encrypted_bytes = base64.b64decode(encrypted_data)
            except binascii.Error:
                # If standard base64 fails, try URL-safe base64
                encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)

            # Check if it's in OpenSSL format (starts with "Salted__")
            if len(encrypted_bytes) < 16 or encrypted_bytes[:8] != b'Salted__':
                logger.error("Not in OpenSSL format (missing 'Salted__' prefix)")
                raise ValueError("Invalid encrypted format - not OpenSSL compatible")

            # Extract salt (next 8 bytes after "Salted__")
            salt = encrypted_bytes[8:16]

            # Extract ciphertext (everything after salt)
            ciphertext = encrypted_bytes[16:]

            # Derive key and IV using OpenSSL's EVP_BytesToKey
            # This is equivalent to OpenSSL's EVP_BytesToKey with MD5, one iteration
            # We need 48 bytes (32 for key, 16 for IV)
            key_iv = self._openssl_kdf(dynamic_key.encode(), salt, 48)
            key = key_iv[:32]  # First 32 bytes for the key
            iv = key_iv[32:48]  # Next 16 bytes for the IV

            # Create AES cipher in CBC mode
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Decrypt and unpad
            try:
                decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                # Return as string
                return decrypted_data.decode('utf-8')
            except ValueError as e:
                logger.error(f"Padding error: {str(e)}")
                # Try without unpadding (in case the frontend didn't pad properly)
                decrypted_data = cipher.decrypt(ciphertext)
                return decrypted_data.decode('utf-8', errors='ignore').rstrip('\0')

        except (ValueError, binascii.Error, UnicodeDecodeError) as e:
            logger.error(f"OpenSSL decryption error: {str(e)}")
            raise ValueError(f"Invalid encrypted data format: {str(e)}")

    def _openssl_kdf(self, password, salt, key_length):
        """
        Derive key using OpenSSL's EVP_BytesToKey with MD5, one iteration.
        This is not the PBKDF2 that we typically recommend for new applications,
        but this matches the default OpenSSL behavior.
        """
        from hashlib import md5

        result = b''
        prev = b''

        # Keep generating key material until we have enough
        while len(result) < key_length:
            prev = md5(prev + password + salt).digest()
            result += prev

        # Return the desired key length
        return result[:key_length]

class UserActivityLogView(APIView):
    permission_classes = [IsAuthenticated]
    @swagger_auto_schema(
        operation_description="View user activity logs (SUPERUSER only)",
        manual_parameters=[
            openapi.Parameter(
                'user_id',
                openapi.IN_QUERY,
                description="Filter logs by specific user ID",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'role',
                openapi.IN_QUERY,
                description="Filter logs by user role (USER, ADMIN)",
                type=openapi.TYPE_STRING,
                enum=['USER', 'ADMIN'],
                required=False
            ),
            openapi.Parameter(
                'start_date',
                openapi.IN_QUERY,
                description="Filter logs from this date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format='date',
                required=False
            ),
            openapi.Parameter(
                'end_date',
                openapi.IN_QUERY,
                description="Filter logs until this date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format='date',
                required=False
            ),
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number for pagination",
                type=openapi.TYPE_INTEGER,
                default=1,
                required=False
            ),
            openapi.Parameter(
                'per_page',
                openapi.IN_QUERY,
                description="Number of logs per page",
                type=openapi.TYPE_INTEGER,
                default=50,
                required=False
            )
        ],
        responses={
            200: openapi.Response(
                description='Activity logs retrieved successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'total_logs': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'per_page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'logs': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(
                                        type=openapi.TYPE_OBJECT,
                                        properties={
                                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                            'user_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                            'username_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'role': openapi.Schema(type=openapi.TYPE_STRING),
                                            'action': openapi.Schema(type=openapi.TYPE_STRING),
                                            'action_display': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                            'timestamp': openapi.Schema(type=openapi.TYPE_STRING, format='date-time')
                                        }
                                    )
                                )
                            }
                        )
                    }
                )
            ),
            400: 'Bad Request - Invalid parameters',
            403: 'Forbidden - Only SUPERUSER can access activity logs'
        }
    )
    @debug_error
    def get(self, request):
        # Check if user is SUPERUSER
        if request.user.role != 'SUPERUSER':
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'Only SUPERUSER can access user activity logs',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)
        try:
            # Import necessary modules
            from datetime import datetime
            from zoneinfo import ZoneInfo
            from .models import ActivityLog

            # Define UTC+7 timezone
            utc_plus_7 = ZoneInfo("Asia/Phnom_Penh")

            # Extract filter parameters
            user_id = request.query_params.get('user_id')
            role = request.query_params.get('role')
            action = request.query_params.get('action')
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')

            # Pagination parameters
            page = int(request.query_params.get('page', 1))
            per_page = int(request.query_params.get('per_page', 50))

            # Base queryset - using the imported ActivityLog model
            logs_query = ActivityLog.objects.select_related('user').order_by('-timestamp')

            # Apply filters
            if user_id:
                logs_query = logs_query.filter(user_id=user_id)

            if role:
                # Filter by user role - only show USER and ADMIN activities
                if role not in ['USER', 'ADMIN']:
                    return Response({
                        'responseCode': status.HTTP_400_BAD_REQUEST,
                        'message': 'Invalid role parameter. Must be USER or ADMIN',
                        'data': None
                    }, status=status.HTTP_400_BAD_REQUEST)
                logs_query = logs_query.filter(role=role)
            else:
                # By default, only show USER and ADMIN activities
                logs_query = logs_query.filter(role__in=['USER', 'ADMIN'])

            if action:
                logs_query = logs_query.filter(action=action)

            if start_date:
                try:
                    start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                    logs_query = logs_query.filter(timestamp__date__gte=start_date)
                except ValueError:
                    return Response({
                        'responseCode': status.HTTP_400_BAD_REQUEST,
                        'message': 'Invalid start_date format. Use YYYY-MM-DD',
                        'data': None
                    }, status=status.HTTP_400_BAD_REQUEST)

            if end_date:
                try:
                    end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
                    logs_query = logs_query.filter(timestamp__date__lte=end_date)
                except ValueError:
                    return Response({
                        'responseCode': status.HTTP_400_BAD_REQUEST,
                        'message': 'Invalid end_date format. Use YYYY-MM-DD',
                        'data': None
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Count total logs for pagination
            total_logs = logs_query.count()
            total_pages = (total_logs + per_page - 1) // per_page  # Ceiling division

            # Apply pagination
            start_index = (page - 1) * per_page
            end_index = start_index + per_page
            paginated_logs = logs_query[start_index:end_index]

            # Format the logs with UTC+7 timezone
            logs_data = []
            for log in paginated_logs:
                # Convert timestamp to UTC+7
                timestamp_utc7 = log.timestamp.astimezone(utc_plus_7)

                log_data = {
                    'id': log.id,
                    'user_id': log.user_id,
                    'username_kh': log.username_kh,
                    'role': log.role,
                    'action': log.action,
                    'action_display': log.get_action_display(),
                    'word_kh': log.word_kh,
                    'word_en': log.word_en,
                    'timestamp': timestamp_utc7.isoformat()  # UTC+7 timestamp
                }
                logs_data.append(log_data)

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'User activity logs retrieved successfully',
                'data': {
                    'logs': logs_data,
                    'total_logs': total_logs,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
            })

        except Exception as e:
            logger.error(f"Error retrieving activity logs: {str(e)}", exc_info=True)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to retrieve activity logs',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
