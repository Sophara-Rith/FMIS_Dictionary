from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from .models import User

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

class UserSerializer(serializers.ModelSerializer):
    """
    Comprehensive User Serializer for CRUD operations
    """
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'password',
            'first_name',
            'last_name',
            'role',
            'phone_number',
            'is_active',
            'date_joined'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True},
            'date_joined': {'read_only': True}
        }

    def create(self, validated_data):
        """
        Custom user creation with role and additional fields
        """
        # Default role to 'USER' if not provided
        role = validated_data.pop('role', 'USER')

        # Create user with hashed password
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )

        # Set additional fields
        user.first_name = validated_data.get('first_name', '')
        user.last_name = validated_data.get('last_name', '')
        user.phone_number = validated_data.get('phone_number', '')
        user.role = role
        user.save()

        return user

    def update(self, instance, validated_data):
        """
        Custom user update with role and permission checks
        """
        # Context from the view to check permissions
        request = self.context.get('request')

        # Role update (admin only)
        role = validated_data.get('role')
        if role:
            # Only allow role change for admin/superuser
            if request and request.user.role not in ['ADMIN', 'SUPERUSER']:
                raise serializers.ValidationError("Only admins can change user roles")
            instance.role = role

        # Update other fields
        instance.email = validated_data.get('email', instance.email)
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)

        # Password update
        password = validated_data.get('password')
        if password:
            instance.set_password(password)

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
    """
    Custom JWT Token Serializer with flexible login
    """
    login_input = serializers.CharField(required=True)

    def validate(self, attrs):
        login_input = attrs.get('login_input')
        password = attrs.get('password')

        if not login_input or not password:
            raise serializers.ValidationError("Must include 'login_input' and 'password'")

        # Try authentication with username
        user = authenticate(username=login_input, password=password)

        # If authentication fails, try with email
        if not user:
            try:
                user_obj = User.objects.get(email=login_input)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                user = None

        if not user:
            raise serializers.ValidationError("Unable to log in with provided credentials")

        # Generate tokens using the authenticated user
        refresh = self.get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user': UserSerializer(user).data
        }
