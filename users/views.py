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
from .models import MobileDevice, User
from .serializers import UserSerializer
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
                                'access': openapi.Schema(type=openapi.TYPE_STRING)
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
                        'access': str(refresh.access_token)
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

class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="View list of all users",
        responses={
            200: openapi.Response(
                description='Users retrieved successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT
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
            # Pagination and filtering logic
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

            # Transform data
            user_data = [{
                'username': user.username,
                'email': user.email,
                'role': user.role
            } for user in paginated_users]

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Data retrieved successfully',
                'data': {
                    'users': user_data
                },
                'total_users': users.count(),
                'page': page,
                'per_page': per_page,
                'total_pages': (users.count() + per_page - 1) // per_page
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Authentication failed',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

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
                'role': openapi.Schema(type=openapi.TYPE_STRING)
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
            serializer = UserSerializer(data=request.data)

            if serializer.is_valid():
                user = serializer.save()
                return Response({
                    'responseCode': status.HTTP_201_CREATED,
                    'message': 'User registered successfully',
                    'data': {
                        'username': user.username,
                        'email': user.email,
                        'role': user.role
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
        # Extract parameters
        device_id = request.data.get('device_id')
        login_input = request.data.get('login_input')
        password = request.data.get('password')
        device_name = request.data.get('device_name')
        device_type = request.data.get('device_type')

        # Detailed debugging
        print("Debug Information:")
        print(f"Device ID: {device_id}")
        print(f"Received login_input: {login_input}")
        print(f"Received password: {password}")
        print(f"Settings Mobile Username: {settings.MOBILE_DEFAULT_USERNAME}")
        print(f"Settings Mobile Password: {settings.MOBILE_DEFAULT_PASSWORD}")

        # Validate required parameters
        if not all([device_id, login_input, password]):
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Missing required parameters',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get mobile default credentials from settings
        mobile_default_username = settings.MOBILE_DEFAULT_USERNAME
        mobile_default_password = settings.MOBILE_DEFAULT_PASSWORD

        # Validate static credentials
        if login_input != mobile_default_username or password != mobile_default_password:
            return Response({
                'responseCode': status.HTTP_401_UNAUTHORIZED,
                'message': 'Invalid login credentials',
                'data': None
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Use default mobile user (ensure this user exists)
            user = User.objects.get(username=mobile_default_username)
        except User.DoesNotExist:
            # Create default mobile user if not exists
            user = User.objects.create_user(
                username=mobile_default_username,
                email=f'{mobile_default_username}@fmis.gov.kh',
                password=mobile_default_password
            )

        try:
            # Find or create mobile device
            device, created = MobileDevice.objects.get_or_create(
                device_id=device_id,
                defaults={
                    'user': user,
                    'is_active': True,
                    'device_name': device_name,
                    'device_type': device_type
                }
            )

            # Generate tokens
            refresh = RefreshToken.for_user(user)

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Mobile login successful',
                'data': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'device_id': device.device_id
                }
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Device registration failed',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
