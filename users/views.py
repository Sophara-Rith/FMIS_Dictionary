# users/views.py
from venv import logger
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from .models import MobileDevice, User
from .serializers import UserSerializer, CustomTokenObtainPairSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from debug_utils import debug_error

User = get_user_model()

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
            200: 'Successful Login',
            400: 'Invalid Credentials',
            401: 'Authentication Failed'
        }
    )
    @debug_error
    def post(self, request):
        # Extract login credentials
        login_input = request.data.get('login_input', '').strip()
        password = request.data.get('password', '').strip()

        # Validate input fields
        if not login_input or not password:
            return Response({
                'error': 'Username/Email and password are required',
                'details': {
                    'login_input': 'Login input cannot be empty',
                    'password': 'Password cannot be empty'
                }
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Attempt to authenticate user
            # Check if login_input is email or username
            user = None
            if '@' in login_input:
                # Login with email
                user = User.objects.filter(email=login_input).first()
            else:
                # Login with username
                user = User.objects.filter(username=login_input).first()

            # Validate user and password
            if user and user.check_password(password):
                # Generate tokens
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'email': user.email,
                        'role': user.role
                    }
                }, status=status.HTTP_200_OK)
            else:
                # Invalid credentials
                return Response({
                    'error': 'Invalid login credentials',
                    'details': 'Username/Email or password is incorrect'
                }, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            # Log the error for debugging
            logger.error(f"Login Error: {str(e)}")
            return Response({
                'error': 'An unexpected error occurred during login',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserRegisterView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="User Registration",
        manual_parameters=[

        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['username', 'email', 'password', 'role'],
            properties={
                'username': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Username"
                ),
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="FMIS email address"
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User password"
                ),
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Phone number"
                ),
                'role': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="USER , ADMIN"
                )
            }
        ),
        responses={
            201: 'User Created Successfully',
            400: 'Registration Error'
        }
    )
    @debug_error
    def post(self, request):
        if request.user.role not in ['SUPERUSER', 'ADMIN']:
            return Response({
                'error': 'You don\'t have the permission to perform this action.'
            }, status=status.HTTP_403_FORBIDDEN)

        requested_role = request.data.get('role', 'USER')

        if request.user.role == 'ADMIN' and requested_role == 'SUPERUSER':
            return Response({
                'error': 'ADMIN cannot create SUPERUSER accounts'
            }, status=status.HTTP_403_FORBIDDEN)

        serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
            try:
                user = serializer.save(role=requested_role)
                return Response({
                    'message': 'User registered successfully',
                    'user': UserSerializer(user).data
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({
                    'error': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserDropView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="Delete User Account (Admin Only)",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="User ID for deletion",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'username',
                openapi.IN_QUERY,
                description="Username for deletion",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'email',
                openapi.IN_QUERY,
                description="User email for deletion",
                type=openapi.TYPE_STRING
            )
        ],
        responses={
            200: openapi.Response(
                description='User Deleted Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Deletion success message'
                        ),
                        'deleted_user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(
                                    type=openapi.TYPE_INTEGER,
                                    description='Deleted user ID'
                                ),
                                'username': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Deleted username'
                                ),
                                'email': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    description='Deleted user email'
                                )
                            }
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def delete(self, request):
        # Multiple ways to identify user for deletion
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
                    'error': 'Identification parameter (id/username/email) is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prevent deleting own account
            if request.user.id == user.id:
                return Response({
                    'error': 'Cannot delete your own account'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Store user details before deletion
            user_details = {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }

            user.delete()
            return Response({
                'message': 'User deleted successfully',
                'deleted_user': user_details
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class UserUpdateView(APIView):
    @swagger_auto_schema(
        operation_description="Update User Profile (Preserves original values if not provided)",
        manual_parameters=[

        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'role': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="User role (ADMIN/USER, admin only)",
                    enum=['USER', 'ADMIN']
                ),
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="New email address"
                ),
                'password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="New password"
                ),
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="New phone number"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='User Updated Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Update success message'
                        ),
                        'user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'username': openapi.Schema(type=openapi.TYPE_STRING),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'role': openapi.Schema(type=openapi.TYPE_STRING),
                                'phone_number': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            ),
            400: 'Validation Error',
            403: 'Unauthorized'
        }
    )
    @debug_error
    def patch(self, request):
        return self._update_user(request, partial=True)

    @debug_error
    def put(self, request):
        # User identification logic
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
                    'error': 'Identification parameter (id/username/email) is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check authorization
            if request.user.id != user.id and request.user.role not in ['ADMIN', 'SUPERUSER']:
                return Response({
                    'error': 'Not authorized to update this user'
                }, status=status.HTTP_403_FORBIDDEN)

            # Prepare update data
            update_data = {}

            # Check and add each field if provided in the request
            if 'role' in request.data:
                update_data['role'] = request.data['role']

            if 'email' in request.data:
                update_data['email'] = request.data['email']

            if 'password' in request.data:
                update_data['password'] = request.data['password']

            if 'phone_number' in request.data:
                update_data['phone_number'] = request.data['phone_number']

            # If no data provided, return current user data
            if not update_data:
                return Response({
                    'message': 'No update data provided',
                    'user': UserSerializer(user).data
                }, status=status.HTTP_200_OK)

            # Add request to serializer context for role validation
            serializer = UserSerializer(
                user,
                data=update_data,
                partial=True,
                context={'request': request}
            )

            if serializer.is_valid():
                updated_user = serializer.save()
                return Response({
                    'message': 'User updated successfully',
                    'user': UserSerializer(updated_user).data,
                    'update_method': 'id' if user_id else 'username' if username else 'email'
                }, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class UserListView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    @swagger_auto_schema(
        operation_description="View list of all user",
        manual_parameters=[

        ],
        responses={
            200: openapi.Response(
                description='User Updated Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Update success message'
                        ),
                        'user': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'username': openapi.Schema(type=openapi.TYPE_STRING),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'role': openapi.Schema(type=openapi.TYPE_STRING),
                                'phone_number': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            ),
            400: 'Validation Error',
            403: 'Unauthorized'
        }
    )
    @debug_error
    def get(self, request):
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

        serializer = UserSerializer(paginated_users, many=True)
        return Response({
            'users': serializer.data,
            'total_users': users.count(),
            'page': page,
            'per_page': per_page,
            'total_pages': (users.count() + per_page - 1) // per_page
        })

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

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
                    'error': 'Identification parameter (id/username/email) is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Ensure user can only access their own profile or admin can access all
            if request.user.id != user.id and request.user.role not in ['ADMIN', 'SUPERUSER']:
                return Response({
                    'error': 'Not authorized to view this user profile'
                }, status=status.HTTP_403_FORBIDDEN)

            serializer = UserSerializer(user)
            return Response({
                'user': serializer.data,
                'lookup_method': 'id' if user_id else 'username' if username else 'email'
            })

        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Obtain JWT Tokens",
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
            200: 'Successful Token Generation',
            400: 'Invalid Credentials'
        }
    )
    @debug_error
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)

class MobileLoginView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Mobile Device Login",
        tags=['mobile'],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['device_id'],
            properties={
                'device_id': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Unique identifier for the mobile device'
                ),
                'device_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Optional name of the device',
                    nullable=True
                ),
                'device_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Optional type of device (iOS/Android)',
                    nullable=True
                ),
                'app_version': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Optional app version',
                    nullable=True
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Successful Login',
                schema=openapi.Schema(
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
                        'device_id': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Device Identifier'
                        )
                    }
                )
            ),
            400: 'Bad Request - Missing Device ID'
        }
    )
    @debug_error
    def post(self, request):
        device_id = request.data.get('device_id')

        if not device_id:
            return Response({
                'error': 'Device ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Use default mobile user (ensure this user exists)
        try:
            user = User.objects.get(username='default_mobile')
        except User.DoesNotExist:
            # Create default mobile user if not exists
            user = User.objects.create_user(
                username=settings.MOBILE_DEFAULT_USERNAME,
                email=f'{settings.MOBILE_DEFAULT_USERNAME}@fmis.gov.kh',
                password=settings.MOBILE_DEFAULT_PASSWORD
            )

        # Find or create mobile device
        mobile_device, created = MobileDevice.objects.get_or_create(
            device_id=device_id,
            defaults={
                'user': user,
                'is_active': True
            }
        )

        # Generate device-specific tokens
        tokens = mobile_device.generate_device_tokens(user)

        return Response({
            'refresh': tokens['refresh_token'],
            'access': tokens['access_token'],
            'device_id': device_id
        })

class CustomTokenRefreshView(TokenRefreshView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="Refresh Mobile Device Token",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                name='X-Device-ID',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Unique identifier for the mobile device',
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['refresh'],
            properties={
                'refresh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Current refresh token'
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Token Refreshed Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='New JWT Access Token'
                        ),
                        'refresh': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='New JWT Refresh Token'
                        )
                    }
                )
            ),
            400: 'Bad Request - Invalid Device or Token'
        }
    )
    @debug_error
    def post(self, request, *args, **kwargs):
        # Get device ID from request
        device_id = request.headers.get('X-Device-ID')

        if not device_id:
            return Response({
                'error': 'Device ID is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find the specific device
            mobile_device = MobileDevice.objects.get(
                device_id=device_id,
                refresh_token=request.data.get('refresh')
            )

            # Refresh tokens for this specific device
            new_tokens = mobile_device.refresh_device_tokens(mobile_device.user)

            return Response({
                'access': new_tokens['access_token'],
                'refresh': new_tokens['refresh_token']
            })

        except MobileDevice.DoesNotExist:
            return Response({
                'error': 'Invalid device or refresh token'
            }, status=status.HTTP_400_BAD_REQUEST)
