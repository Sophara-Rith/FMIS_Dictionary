from rest_framework import serializers
from django.contrib.auth import authenticate
from django.db.models import Q
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'password',
            'first_name', 'last_name', 'role'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True}
        }

    def validate_email(self, value):
        # Ensure email is from @fmis.gov.kh domain
        if not value.endswith('@fmis.gov.kh'):
            raise serializers.ValidationError("Email must be from @fmis.gov.kh domain")
        return value

    def create(self, validated_data):
        # Extract first and last name from email if not provided
        email = validated_data['email']
        email_parts = email.split('@')[0].split('.')

        if len(email_parts) >= 2:
            validated_data['last_name'] = email_parts[0].capitalize()
            validated_data['first_name'] = email_parts[1].capitalize()

        # Generate username from email
        username = f"{email_parts[0]}_{email_parts[1]}" if len(email_parts) >= 2 else email.split('@')[0]
        validated_data['username'] = username

        return User.objects.create_user(**validated_data)

class LoginSerializer(serializers.Serializer):
    login_input = serializers.CharField()  # Can be username or email
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        login_input = data.get('login_input')
        password = data.get('password')

        if login_input and password:
            # Try to authenticate with either username or email
            user = None
            try:
                # First, try to find user by username or email
                user = User.objects.filter(
                    Q(username=login_input) | Q(email=login_input)
                ).first()
            except User.DoesNotExist:
                pass

            if user:
                # Authenticate the user
                auth_user = authenticate(username=user.username, password=password)
                if auth_user:
                    data['user'] = auth_user
                    return data

            raise serializers.ValidationError("Unable to login with provided credentials")
        else:
            raise serializers.ValidationError("Must include login input and password")
