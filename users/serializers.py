from rest_framework import serializers
from django.contrib.auth import authenticate
from django.utils import timezone
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'password',
            'first_name', 'last_name', 'role',
            'is_suspended', 'date_joined'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True},
            'is_suspended': {'read_only': True},
            'date_joined': {'read_only': True}
        }

    def create(self, validated_data):
        # Only admins can specify role
        role = validated_data.pop('role', 'USER')

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            role=role
        )

        # Optional fields
        user.first_name = validated_data.get('first_name', '')
        user.last_name = validated_data.get('last_name', '')
        user.save()

        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            # Fetch the user
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                raise serializers.ValidationError("User not found.")

            # Check if login attempts are allowed
            if not user.can_attempt_login():
                if user.is_suspended:
                    raise serializers.ValidationError("Account is suspended due to multiple failed login attempts.")
                else:
                    raise serializers.ValidationError("Too many failed login attempts. Please try again later.")

            # Authenticate user
            auth_user = authenticate(username=username, password=password)

            if auth_user:
                # Successful login - reset attempts
                user.reset_login_attempts()
                data['user'] = auth_user
                return data
            else:
                # Failed login attempt
                user.increment_login_attempts()
                raise serializers.ValidationError("Unable to login with provided credentials.")
        else:
            raise serializers.ValidationError("Must include 'username' and 'password'.")

class UserManagementSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name',
            'last_name', 'role', 'is_suspended'
        ]
        read_only_fields = ['id']
