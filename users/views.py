# users/views.py
import logging
from venv import logger
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenBlacklistView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .models import MobileDevice, User, UserComment
from .serializers import UserSerializer, UserCommentSerializer, UserCommentSubmitSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

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
                    description="Username or Email"
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User password"
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
                                        'phone_number': openapi.Schema(type=openapi.TYPE_STRING)
                                    }
                                )
                            }
                        )
                    }
                )
            )
        }
    )
    def post(self, request):
        # Extract login credentials
        login_input = request.data.get('login_input', '').strip()
        password = request.data.get('password', '').strip()

        # Validate input fields
        if not login_input or not password:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Username/Email and password are required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Attempt to authenticate user
            user = None
            if '@' in login_input:
                user = User.objects.filter(email=login_input).first()
            else:
                user = User.objects.filter(username=login_input).first()

            # Validate user and password
            if user and user.check_password(password):
                # Generate tokens
                refresh = RefreshToken.for_user(user)

                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'message': 'Login successful',
                    'data': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token),
                        'user': {
                            'username': user.username,
                            'username_kh': user.username_kh or '',
                            'email': user.email,
                            'staff_id': convert_to_khmer_number(user.staff_id) if user.staff_id else '',
                            'position': user.position or '',
                            'phone_number': convert_to_khmer_number(user.phone_number) if user.phone_number else '',
                            'role': user.role or ''
                        }
                    }
                }, status=status.HTTP_200_OK)
            else:
                # Invalid credentials
                return Response({
                    'responseCode': status.HTTP_401_UNAUTHORIZED,
                    'message': 'Invalid login credentials',
                    'data': None
                }, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'An unexpected error occurred during login',
                'data': None
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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

class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="View list of all users",
        manual_parameters=[
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'per_page',
                openapi.IN_QUERY,
                description="Number of items per page",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'role',
                openapi.IN_QUERY,
                description="Filter by user role",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'is_active',
                openapi.IN_QUERY,
                description="Filter by active status",
                type=openapi.TYPE_BOOLEAN
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
                                            'staff_id': openapi.Schema(type=openapi.TYPE_STRING),
                                            'username_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'sex': openapi.Schema(type=openapi.TYPE_STRING),
                                            'position': openapi.Schema(type=openapi.TYPE_STRING),
                                            'email': openapi.Schema(type=openapi.TYPE_STRING),
                                            'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
                                            'date_joined': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                                            'role': openapi.Schema(type=openapi.TYPE_STRING)
                                        }
                                    )
                                ),
                                'total_users': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'per_page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER)
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
            # Support pagination and filtering
            page = int(request.query_params.get('page', 1))
            per_page = int(request.query_params.get('per_page', 25))
            role = request.query_params.get('role')
            is_active = request.query_params.get('is_active')

            # Base queryset
            users = User.objects.all()

            # Apply filters
            if role:
                users = users.filter(role=role)
            if is_active is not None:
                users = users.filter(is_active=is_active.lower() == 'true')

            # Pagination
            start = (page - 1) * per_page
            end = start + per_page
            paginated_users = users[start:end]

            # Transform data to include specified fields
            user_data = [{
                'staff_id': convert_to_khmer_number(user.staff_id) if user.staff_id else '',
                'username_kh': user.username_kh or '',
                'sex': user.sex or '',
                'position': user.position or '',
                'email': user.email,
                'phone_number': convert_to_khmer_number(user.phone_number) if user.phone_number else '',
                'date_joined': convert_to_khmer_number(format_date(user.date_joined)) if format_date(user.date_joined) else '',
                'role': user.role
            } for user in paginated_users]

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Data retrieved successfully',
                'data': {
                    'users': user_data,
                    'total_users': users.count(),
                    'page': page,
                    'per_page': per_page,
                    'total_pages': (users.count() + per_page - 1) // per_page
                }
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Data retrieval failed',
                'data': str(e)
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
                'username': user.username,
                'email': user.email,
                'role': user.role
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
            required=['username', 'email', 'password', 'role'],
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
                'role': openapi.Schema(type=openapi.TYPE_STRING),
                'sex': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    enum=['MALE', 'FEMALE', 'OTHER', 'PREFER_NOT_TO_SAY'],
                    description='User\'s sex/gender'
                ),
                'username_kh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Khmer Username'
                ),
                'staff_id': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Staff Identification Number'
                ),
                'position': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Job Position'
                ),
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Phone number in format 0XXXXXXXXX'
                ),
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
                                'username_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                'staff_id': openapi.Schema(type=openapi.TYPE_STRING),
                                'position': openapi.Schema(type=openapi.TYPE_STRING),
                                'phone_number': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            ),
            401: openapi.Response(
                description='Unauthorized',
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
        # Check authentication
        if not request.user or not request.user.is_authenticated:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Authentication required',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check authorization
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'You do not have permission to perform this action',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            phone_number = request.data.get('phone_number')
            if phone_number:
                # Validate phone number format
                cleaned_number = ''.join(filter(str.isdigit, str(phone_number)))
                if not (cleaned_number.startswith('0') and len(cleaned_number) in [9, 10]):
                    return Response({
                        'responseCode': status.HTTP_400_BAD_REQUEST,
                        'message': 'Invalid phone number format',
                        'data': None
                    }, status=status.HTTP_400_BAD_REQUEST)

            serializer = UserSerializer(data=request.data)

            if serializer.is_valid():
                user = serializer.save()
                return Response({
                    'responseCode': status.HTTP_201_CREATED,
                    'message': 'User registered successfully',
                    'data': {
                        'username': user.username,
                        'email': user.email,
                        'role': user.role,
                        'sex': user.sex,
                        'username_kh': user.username_kh,
                        'staff_id': user.staff_id,
                        'position': user.position,
                        'phone_number': user.phone_number
                    }
                }, status=status.HTTP_201_CREATED)

            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Validation error',
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Registration failed',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
            403: openapi.Response(
                description='Forbidden',
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
    def delete(self, request):
        # Check authentication
        if not request.user or not request.user.is_authenticated:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Authentication required',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        # Check authorization
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'You do not have permission to perform this action',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            # User identification parameters
            user_id = request.query_params.get('id')
            username = request.query_params.get('username')
            email = request.query_params.get('email')

            # Find user
            user = None
            if user_id:
                user = get_object_or_404(User, id=user_id)
            elif username:
                user = get_object_or_404(User, username=username)
            elif email:
                user = get_object_or_404(User, email=email)
            else:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Identification parameter required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prevent deleting own account
            if request.user.id == user.id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Cannot delete own account',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Specific check: Only SUPERUSER can delete ADMIN accounts
            if user.role == 'ADMIN' and request.user.role != 'SUPERUSER':
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'Only SUPERUSER can delete ADMIN accounts',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Store user details before deletion
            user_details = {
                'username': user.username,
                'email': user.email,
                'role': user.role
            }

            # Delete user
            user.delete()

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'User deleted successfully',
                'data': user_details
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Deletion failed',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update User Profile",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING),
                'email': openapi.Schema(type=openapi.TYPE_STRING),
                'role': openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={
            200: openapi.Response(
                description='User Updated Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            401: openapi.Response(
                description='Unauthorized',
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
    def put(self, request):
        # Check authentication
        if not request.user or not request.user.is_authenticated:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Authentication required',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Find user to update
            user = request.user

            # Validate and update user
            serializer = UserSerializer(
                user,
                data=request.data,
                partial=True,
                context={'request': request}
            )

            if serializer.is_valid():
                updated_user = serializer.save()
                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'message': 'User updated successfully',
                    'data': {
                        'username': updated_user.username,
                        'email': updated_user.email,
                        'role': updated_user.role
                    }
                })

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
                                'user': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'username': openapi.Schema(type=openapi.TYPE_STRING),
                                        'username_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                        'email': openapi.Schema(type=openapi.TYPE_STRING),
                                        'staff_id': openapi.Schema(type=openapi.TYPE_STRING),
                                        'position': openapi.Schema(type=openapi.TYPE_STRING),
                                        'phone_number': openapi.Schema(type=openapi.TYPE_STRING)
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
    def post(self, request, *args, **kwargs):
        try:
            # Override the request data to use login_input
            login_input = request.data.get('login_input')
            password = request.data.get('password')

            # Modify request data to match TokenObtainPairSerializer
            request.data['username'] = login_input

            # Call parent method
            response = super().post(request, *args, **kwargs)

            # Find the user for additional details
            user = User.objects.get(username=login_input)

            # Enhance response with login method and user details
            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Token generated successfully',
                'data': {
                    'refresh': response.data.get('refresh'),
                    'access': response.data.get('access'),
                    'user': {
                        'username': user.username,
                        'username_kh': user.username_kh or '',
                        'email': user.email,
                        'staff_id': user.staff_id or '',
                        'position': user.position or '',
                        'phone_number': user.phone_number or ''
                    }
                }
            })

        except User.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'User not found',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

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
    def post(self, request, *args, **kwargs):
        try:
            # Call parent method to get new tokens
            response = super().post(request, *args, **kwargs)

            # Create a new response with the desired structure
            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Token refreshed successfully',
                'data': {
                    'refresh': response.data.get('refresh'),
                    'access': response.data.get('access')
                }
            })
        except Exception as e:
            # Log the exception for debugging
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
                    description="User's username",
                    example="johndoe"
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

    def post(self, request):
        # Specific mobile login credentials
        MOBILE_LOGIN_USERNAME = 'fmis369'
        MOBILE_LOGIN_PASSWORD = 'Fmis@dic2O@$'

        # Extract parameters
        device_id = request.data.get('device_id')
        login_input = request.data.get('login_input')
        password = request.data.get('password')

        # Validate required parameters
        if not all([device_id, login_input, password]):
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Missing required parameters',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate login credentials specifically for mobile
        if (login_input != MOBILE_LOGIN_USERNAME or
            password != MOBILE_LOGIN_PASSWORD):
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Invalid mobile credentials',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Find or create mobile user
            user, created = User.objects.get_or_create(
                username=MOBILE_LOGIN_USERNAME,
                defaults={
                    'email': f'{MOBILE_LOGIN_USERNAME}@mobile.app',
                    'is_active': True
                }
            )

            # Set password only if user is newly created
            if created:
                user.set_password(MOBILE_LOGIN_PASSWORD)
                user.save()

            # Create or update mobile device
            mobile_device, device_created = MobileDevice.objects.get_or_create(
                device_id=device_id,
                defaults={
                    'user': user,
                    'is_active': True
                }
            )

            # Generate mobile-specific tokens with 3-day lifetime
            from rest_framework_simplejwt.tokens import RefreshToken
            refresh = RefreshToken.for_user(user)

            # Optional: Add custom claims
            refresh['device_id'] = device_id

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Mobile login successful',
                'data': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'device_id': device_id,
                }
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Mobile login failed',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class PublicTestEndpoint(APIView):
    permission_classes = [AllowAny]  # No authentication required

    @swagger_auto_schema(
        operation_description="Public Test Endpoint - No Authentication Required",
        responses={
            200: openapi.Response(
                description='Successful Test Response',
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
                            description='Test endpoint message',
                            example='API is working perfectly!'
                        ),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'timestamp': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Current server timestamp'
                                ),
                                'version': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='API version'
                                )
                            }
                        )
                    }
                )
            )
        }
    )
    def get(self, request):
        from datetime import datetime

        return Response({
            'responseCode': status.HTTP_200_OK,
            'message': 'API is working perfectly!',
            'data': {
                'timestamp': datetime.now().isoformat(),
                'version': 'v0.8'
            }
        })

class UserCommentSubmitView(APIView):
    """
    Endpoint for mobile users to submit comments
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Submit User Comment from Mobile App",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                description="Unique device identifier",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['detail'],
            properties={
                'detail': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User's comment text",
                    example="I found an issue with the app..."
                )
            }
        ),
        responses={
            201: openapi.Response(
                description='Comment Submitted Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'detail': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            )
        }
    )
    def post(self, request):
        device_id = request.headers.get('X-Device-ID')

        # Validate device_id
        if not device_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Device ID is required in X-Device-ID header',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate comment detail
        detail = request.data.get('detail', '').strip()
        if not detail:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Comment detail cannot be empty',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Create comment
            comment = UserComment.objects.create(
                user=request.user,
                detail=detail,
                device_id=device_id
            )

            return Response({
                'responseCode': status.HTTP_201_CREATED,
                'message': 'Comment submitted successfully',
                'data': {
                    'id': comment.id,
                    'detail': comment.detail
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to submit comment',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserCommentListView(APIView):
    """
    Endpoint for ADMIN and SUPERUSER to view all user comments
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve All User Comments (ADMIN/SUPERUSER only)",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'is_reviewed',
                openapi.IN_QUERY,
                description="Filter by review status",
                type=openapi.TYPE_BOOLEAN
            )
        ],
        responses={
            200: openapi.Response(
                description='Comments Retrieved Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'comments': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(
                                        type=openapi.TYPE_OBJECT,
                                        properties={
                                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                            'username': openapi.Schema(type=openapi.TYPE_STRING),
                                            'comment_text': openapi.Schema(type=openapi.TYPE_STRING),
                                            'created_at': openapi.Schema(type=openapi.TYPE_STRING),
                                            'device_id': openapi.Schema(type=openapi.TYPE_STRING),
                                            'is_reviewed': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                                        }
                                    )
                                ),
                                'total_comments': openapi.Schema(type=openapi.TYPE_INTEGER)
                            }
                        )
                    }
                )
            )
        }
    )
    def get(self, request):
        # Check if user is ADMIN or SUPERUSER
        if request.user.role not in ['ADMIN', 'SUPERUSER']:
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'You do not have permission to perform this action',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        # Base queryset
        comments = UserComment.objects.all()

        # Optional filtering by review status
        is_reviewed = request.query_params.get('is_reviewed')
        if is_reviewed is not None:
            comments = comments.filter(is_reviewed=is_reviewed.lower() == 'true')

        # Serialize all comments
        serializer = UserCommentSerializer(comments, many=True)

        return Response({
            'responseCode': status.HTTP_200_OK,
            'message': 'All comments retrieved successfully',
            'data': {
                'comments': serializer.data,
                'total_comments': comments.count()
            }
        })
