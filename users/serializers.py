# users/serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
import re
from .models import User, UserComment

def format_phone_number(phone_number):
    """
    Format phone number by splitting into groups of 3 digits

    Examples:
    - 092457452 -> 092 457 452
    - 0964567890 -> 096 456 7890
    """
    # Remove any existing spaces or non-digit characters
    cleaned_number = ''.join(filter(str.isdigit, str(phone_number)))

    # Handle different phone number lengths
    if len(cleaned_number) < 9:
        return cleaned_number  # Return original if too short

    # Different formatting based on number length
    if len(cleaned_number) == 9:
        # Standard 9-digit number (092457452)
        return f"{cleaned_number[:3]} {cleaned_number[3:6]} {cleaned_number[6:]}"
    elif len(cleaned_number) == 10:
        # 10-digit number (0964567890)
        return f"{cleaned_number[:3]} {cleaned_number[3:6]} {cleaned_number[6:]}"
    else:
        # For longer numbers, use a more flexible approach
        return ' '.join([
            cleaned_number[:3],  # First 3 digits
            cleaned_number[3:6],  # Next 3 digits
            cleaned_number[6:]    # Remaining digits
        ])

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
            'username',
            'username_kh',
            'email',
            'password',
            'phone_number',
            'role',
            'staff_id',
            'position',
            'sex'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True},
            'phone_number': {'required': False},
            'username_kh': {'required': False},
            'staff_id': {'required': False},
            'position': {'required': False},
            'sex': {'required': False}
        }

    def validate_phone_number(self, value):
        """
        Validate phone number format
        """
        if not value:
            return value

        # Remove non-digit characters
        cleaned_number = ''.join(filter(str.isdigit, str(value)))

        # Validate number length and format
        if not cleaned_number:
            raise serializers.ValidationError("Phone number must contain digits")

        # Optional: Add specific validation for Cambodian phone numbers
        if not (cleaned_number.startswith('0') and len(cleaned_number) in [9, 10]):
            raise serializers.ValidationError("Invalid phone number format")

        return value

    def validate_password(self, password):
        """
        Custom password validation during serializer validation
        """
        return PasswordValidator.validate_password(password)

    def create(self, validated_data):

        sex = validated_data.pop('sex', None)
        phone_number = validated_data.get('phone_number')
        if phone_number:
            validated_data['phone_number'] = format_phone_number(phone_number)

        username_kh = validated_data.pop('username_kh', '')
        staff_id = validated_data.pop('staff_id', '')
        position = validated_data.pop('position', '')

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            phone_number=validated_data.get('phone_number'),
            role=validated_data.get('role')
        )

        user.username_kh = username_kh
        user.staff_id = staff_id
        user.position = position
        user.sex = sex
        user.save()

        return user

    def update(self, instance, validated_data):
        instance.username_kh = validated_data.get('username_kh', instance.username_kh)
        instance.staff_id = validated_data.get('staff_id', instance.staff_id)
        instance.position = validated_data.get('position', instance.position)
        instance.sex = validated_data.get('sex', instance.sex)

        return super().update(instance, validated_data)

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

class UserCommentSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()

    class Meta:
        model = UserComment
        fields = [
            'id',
            'username',
            'detail',
            'device_id',
            'created_at',
            'is_reviewed'
        ]
        read_only_fields = ['id', 'created_at']

    def get_username(self, obj):
        return obj.user.username

class UserCommentSubmitSerializer(serializers.ModelSerializer):
    """
    Serializer specifically for mobile app comment submission
    """
    class Meta:
        model = UserComment
        fields = ['detail', 'device_id']

    def create(self, validated_data):
        # Get the current authenticated user
        user = self.context['request'].user

        # Create comment with the current user
        comment = UserComment.objects.create(
            user=user,
            detail=validated_data['detail'],
            device_id=validated_data.get('device_id')
        )
        return comment
