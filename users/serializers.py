# users/serializers.py
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from django.db.models import Max
import re

from .utils import convert_to_khmer_date, format_phone_number
from .models import User, UserComment

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

class StaffIDGenerator:
    @classmethod
    def generate_next_staff_id(cls):
        """
        Generate the next staff ID in the format: ប.គ.ហ - XXXX

        Example sequence:
        - ប.គ.ហ - 0001
        - ប.គ.ហ - 0002
        - ប.គ.ហ - 0003
        """
        # Get the maximum existing staff ID
        max_staff_id = User.objects.filter(
            staff_id__regex=r'^ប\.គ\.ហ - \d{4}$'
        ).aggregate(
            Max('staff_id')
        )['staff_id__max']

        # If no existing staff ID, start from 0001
        if not max_staff_id:
            return 'ប.គ.ហ - 0001'

        # Extract the numeric part and increment
        try:
            # Split the existing staff ID and get the numeric part
            current_number = int(max_staff_id.split('-')[-1].strip())
            next_number = current_number + 1

            # Format the new staff ID with leading zeros
            return f'ប.គ.ហ - {next_number:04d}'

        except (ValueError, IndexError):
            # Fallback to a default if parsing fails
            return 'ប.គ.ហ - 0001'

    def format_phone_number(phone_number):
        """
        Format phone number by splitting into groups of 3 digits
        """
        # Remove any existing spaces or non-digit characters
        cleaned_number = ''.join(filter(str.isdigit, str(phone_number)))

        # Handle different phone number lengths
        if len(cleaned_number) < 9:
            return cleaned_number  # Return original if too short

        # Different formatting based on number length
        if len(cleaned_number) == 9:
            return f"{cleaned_number[:3]} {cleaned_number[3:6]} {cleaned_number[6:]}"
        elif len(cleaned_number) == 10:
            return f"{cleaned_number[:3]} {cleaned_number[3:6]} {cleaned_number[6:]}"
        else:
            return ' '.join([
                cleaned_number[:3],  # First 3 digits
                cleaned_number[3:6],  # Next 3 digits
                cleaned_number[6:]    # Remaining digits
            ])

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'username',
            'email',
            'password',
            'role',
            'sex',
            'username_kh',
            'position',
            'phone_number',
            'staff_id',
            'first_name',
            'last_name'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'username': {'required': False},
            'email': {'required': True},
            'role': {'required': False},
            'staff_id': {'read_only': True},
        }

    def validate_email(self, email):
        """
        Validate email domain
        """
        if not email.endswith('@fmis.gov.kh'):
            raise serializers.ValidationError("Only FMIS email addresses are allowed")
        return email

    def validate_password(self, password):
        """
        Validate password complexity
        """
        return PasswordValidator.validate_password(password)

    def validate_phone_number(self, phone_number):
        """
        Validate and format phone number
        """
        if not phone_number:
            return phone_number

        # Remove non-digit characters
        cleaned_number = ''.join(filter(str.isdigit, str(phone_number)))

        # Validate number length and format
        if not cleaned_number:
            raise serializers.ValidationError("Phone number must contain digits")

        return format_phone_number(phone_number)

    def create(self, validated_data):
        # Extract username from email
        email = validated_data.get('email', '')
        username = email.split('@')[0] if email else ''
        validated_data['username'] = username

        # Generate staff ID automatically
        staff_id = StaffIDGenerator.generate_next_staff_id()
        validated_data['staff_id'] = staff_id

        # Format phone number if provided
        phone_number = validated_data.get('phone_number')
        if phone_number:
            validated_data['phone_number'] = format_phone_number(phone_number)

        # Set default role if not provided
        role = validated_data.get('role', 'USER')
        validated_data['role'] = role

        # Extract first and last name from email if not provided
        if not validated_data.get('first_name') or not validated_data.get('last_name'):
            email_parts = email.split('@')[0].split('.')
            if len(email_parts) >= 2:
                validated_data['last_name'] = email_parts[0].capitalize()
                validated_data['first_name'] = email_parts[1].capitalize()

        # Create user
        user = User.objects.create_user(**validated_data)
        return user

    def update(self, instance, validated_data):
        # Password update with validation
        password = validated_data.get('password')
        if password:
            try:
                # Validate password before updating
                validated_password = PasswordValidator.validate_password(password)

                # Additional check: Prevent using previous passwords
                if instance.check_password(password):
                    raise serializers.ValidationError(
                        "New password must be different from the current password."
                    )

                # Set new password using validated password
                instance.set_password(validated_password)
            except serializers.ValidationError as e:
                raise serializers.ValidationError({'password': str(e)})

        # Update other fields
        instance.email = validated_data.get('email', instance.email)
        instance.role = validated_data.get('role', instance.role)
        instance.sex = validated_data.get('sex', instance.sex)
        instance.username_kh = validated_data.get('username_kh', instance.username_kh)
        instance.position = validated_data.get('position', instance.position)

        # Format and update phone number
        phone_number = validated_data.get('phone_number')
        if phone_number:
            instance.phone_number = format_phone_number(phone_number)

        # Update first and last name
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)

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

class UserCommentSerializer(serializers.ModelSerializer):
    username = serializers.SerializerMethodField()
    created_at = serializers.SerializerMethodField()

    class Meta:
        model = UserComment
        fields = [
            'id',
            'username',
            'detail',
            'user_id',
            'device_id',
            'created_at',
            'is_reviewed'
        ]
        read_only_fields = ['id', 'created_at']

    def get_username(self, obj):
        return obj.user.username if obj.user else None

    def get_created_at(self, obj):
        return convert_to_khmer_date(obj.created_at.strftime('%d-%m-%Y')) if obj.created_at else None

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
