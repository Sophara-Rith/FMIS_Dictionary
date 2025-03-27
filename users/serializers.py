# users/serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
import re
from .models import User, MobileDevice

class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login with flexible authentication
    """
    username = serializers.CharField(
        required=False,
        help_text="Username for login (optional if email is provided)"
    )
    email = serializers.EmailField(
        required=False,
        help_text="Email for login (optional if username is provided)"
    )
    password = serializers.CharField(
        required=True,
        write_only=True,
        help_text="User password"
    )

    def validate(self, data):
        # Validate that either username or email is provided
        if not (data.get('username') or data.get('email')):
            raise serializers.ValidationError("Either username or email is required")

        # Authenticate user
        login_input = data.get('username') or data.get('email')
        password = data.get('password')

        user = authenticate(username=login_input, password=password)

        if not user:
            try:
                # Try authentication with email
                user_obj = User.objects.get(email=login_input)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None

        if not user:
            raise serializers.ValidationError("Invalid login credentials")

        if not user.is_active:
            raise serializers.ValidationError("User account is disabled")

        data['user'] = user
        return data

class PasswordValidator:
    @staticmethod
    def validate_password(password):
        """
        Validate password complexity:
        - At least 8 characters long
        - Contains at least 1 uppercase letter
        - Contains at least 1 lowercase letter
        - Contains at least 1 special character
        - Contains at least 1 number
        """
        # Check length
        if len(password) < 8:
            raise serializers.ValidationError(
                "Password must be at least 8 characters long."
            )

        # Check for at least 1 uppercase letter
        if not re.search(r'[A-Z]', password):
            raise serializers.ValidationError(
                "Password must contain at least 1 uppercase letter."
            )

        # Check for at least 1 lowercase letter
        if not re.search(r'[a-z]', password):
            raise serializers.ValidationError(
                "Password must contain at least 1 lowercase letter."
            )

        # Check for at least 1 special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise serializers.ValidationError(
                "Password must contain at least 1 special character (!@#$%^&*(),.?\":{}|<>)."
            )

        # Check for at least 1 number
        if not re.search(r'\d', password):
            raise serializers.ValidationError(
                "Password must contain at least 1 number."
            )

        return password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'password',
            'role', 'phone_number'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True},
            'phone_number': {'required': False}
        }

    def validate_password(self, password):
        """
        Custom password validation during serializer validation
        """
        return PasswordValidator.validate_password(password)

    def create(self, validated_data):
        password = validated_data.pop('password')

        try:
            PasswordValidator.validate_password(password)
        except serializers.ValidationError as e:
            raise serializers.ValidationError({'password': str(e)})

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=password,
            phone_number=validated_data.get('phone_number')
        )
        return user

    def update(self, instance, validated_data):
        # Password update with validation
        password = validated_data.get('password')

        if password:
            # Validate password before updating
            try:
                PasswordValidator.validate_password(password)
            except serializers.ValidationError as e:
                raise serializers.ValidationError({'password': str(e)})

            # Set new password
            instance.set_password(password)

        # Update other fields
        instance.email = validated_data.get('email', instance.email)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)

        instance.save()
        return instance

class UserManagementSerializer(serializers.ModelSerializer):
    """
    Serializer for admin user management
    """
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'first_name',
            'last_name',
            'role',
            'is_active',
            'date_joined',
            'last_login'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    # Remove the default username and password fields
    login_input = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

    def __init__(self, *args, **kwargs):
        # Override the default fields to remove username and password
        super().__init__(*args, **kwargs)
        self.fields.pop('username', None)
        self.fields.pop('password', None)

    def validate(self, attrs):
        # Manually add login_input and password to attrs
        login_input = self.initial_data.get('login_input')
        password = self.initial_data.get('password')

        if not login_input or not password:
            raise serializers.ValidationError({
                "error": "Both login_input and password are required"
            })

        # Try to authenticate with username or email
        user = None
        try:
            # First, try authenticating with username
            user = authenticate(username=login_input, password=password)

            # If username auth fails, try with email
            if not user:
                try:
                    user_obj = User.objects.get(email=login_input)
                    user = authenticate(username=user_obj.username, password=password)
                except User.DoesNotExist:
                    user = None
        except Exception as e:
            raise serializers.ValidationError({
                "error": "Authentication failed"
            })

        if not user:
            raise serializers.ValidationError({
                "error": "Invalid credentials"
            })

        # Manually set username and password for parent class
        attrs['username'] = user.username
        attrs['password'] = password

        # Use the parent class method to generate tokens
        refresh = super().get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        }

# class MobileLoginSerializer(serializers.Serializer):

#     class Meta:
#         model = MobileDevice
#         fields = [
#             'device_id',
#             'last_login',
#             'is_active',
#             'created_at',
#             'app_version',
#             'device_model',
#             'device_os'
#         ]

#     login_input = serializers.CharField()
#     password = serializers.CharField(write_only=True)
#     device_id = serializers.CharField(max_length=255)

#     def validate(self, data):
#         # Validate login credentials (similar to existing login logic)
#         login_input = data.get('login_input')
#         password = data.get('password')
#         device_id = data.get('device_id')

#         # Authenticate user
#         user = authenticate(username=login_input, password=password)

#         if not user:
#             try:
#                 # Try authentication with email
#                 user_obj = User.objects.get(email=login_input)
#                 user = authenticate(username=user_obj.username, password=password)
#             except User.DoesNotExist:
#                 user = None

#         if not user:
#             raise serializers.ValidationError("Invalid login credentials")

#         # Store or update device information
#         mobile_device, created = MobileDevice.objects.get_or_create(
#             device_id=device_id,
#             defaults={'user': user}
#         )

#         # Update last login if device exists
#         if not created:
#             mobile_device.user = user
#             mobile_device.save()

#         # Generate tokens
#         refresh = RefreshToken.for_user(user)

#         data['user'] = user
#         data['refresh'] = str(refresh)
#         data['access'] = str(refresh.access_token)

#         return data
