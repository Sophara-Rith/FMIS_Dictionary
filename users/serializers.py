from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import authenticate
from .models import User

class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login
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
        if not (data.get('username') or data.get('email')):
            raise serializers.ValidationError("Either username or email is required")
        return data

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'password',
            'role', 'phone_number'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True}
        }

    def update(self, instance, validated_data):

        request = self.context.get('request')

        # Role update (admin only)
        role = validated_data.get('role')
        if role:
            # Only allow role change for admin/superuser
            if request.user.role not in ['ADMIN', 'SUPERUSER']:
                raise serializers.ValidationError("Only admins can change user roles")
            instance.role = role

        email = validated_data.get('email')
        if email:
            instance.email = email

        password = validated_data.get('password')
        if password:
            instance.set_password(password)

        phone_number = validated_data.get('phone_number')
        if phone_number:
            instance.phone_number = phone_number

        instance.save()
        return instance

    def create(self, validated_data):
        phone_number = validated_data.pop('phone_number', None)

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )

        if phone_number:
            user.phone_number = phone_number

        user.save()
        return user

class UserManagementSerializer(serializers.ModelSerializer):
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

    username = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    login_input = serializers.CharField(required=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields.pop('username', None)
        self.fields['login_input'] = serializers.CharField(required=True)

    def validate(self, attrs):

        login_input = attrs.get('login_input')
        password = attrs.get('password')

        if not login_input or not password:
            raise serializers.ValidationError("Must include 'login_input' and 'password'")

        user = authenticate(username=login_input, password=password)

        # If authentication fails, try with email
        if not user:
            try:
                user = User.objects.get(email=login_input)

                if user.check_password(password):
                    user = authenticate(username=user.username, password=password)
            except User.DoesNotExist:
                user = None

        if not user:
            raise serializers.ValidationError("Unable to log in with provided credentials")

        # Generate tokens using the authenticated user
        refresh = self.get_token(user)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
