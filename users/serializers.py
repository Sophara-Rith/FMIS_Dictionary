# users/serializers.py
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from .models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'password',
            'first_name',
            'last_name',
            'phone_number',
            'role'
        ]
        extra_kwargs = {
            'password': {'write_only': True},
            'id': {'read_only': True},
            'role': {'required': False}
        }

    def create(self, validated_data):
        # Default role to 'USER' if not provided
        role = validated_data.pop('role', 'USER')

        # Create user
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        user.first_name = validated_data.get('first_name', '')
        user.last_name = validated_data.get('last_name', '')
        user.phone_number = validated_data.get('phone_number', '')
        user.role = validated_data.get('role', 'USER')
        user.save()

        return user

    def update(self, instance, validated_data):
        # Handle role update
        role = validated_data.pop('role', None)
        if role:
            instance.role = role

        # Update other fields
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)

        instance.save()
        return instance

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    raise serializers.ValidationError("User account is disabled.")
                data['user'] = user
                return data
            else:
                raise serializers.ValidationError("Unable to login with provided credentials.")
        else:
            raise serializers.ValidationError("Must include 'username' and 'password'.")
