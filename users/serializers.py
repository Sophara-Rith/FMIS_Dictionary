from rest_framework import serializers
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

        # Set additional fields
        user.first_name = validated_data.get('first_name', '')
        user.last_name = validated_data.get('last_name', '')
        user.phone_number = validated_data.get('phone_number', '')

        # Set role if provided or use default
        user.role = role
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
        instance.phone_number = validated_data.get('phone_number', instance.phone_number)

        instance.save()
        return instance
