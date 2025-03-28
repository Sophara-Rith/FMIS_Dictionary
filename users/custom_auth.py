# users/custom_auth.py
from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import TokenAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.conf import settings
from .models import MobileDevice

class ExpiringTokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        try:
            # Get the token
            token = self.model.objects.get(key=key)
        except self.model.DoesNotExist:
            raise AuthenticationFailed('Invalid token')

        # Check if token is associated with a user
        if not token.user.is_active:
            raise AuthenticationFailed('User inactive or deleted')

        # Calculate token expiration time
        token_expiry_time = getattr(settings, 'TOKEN_EXPIRE_TIME', 90)  # 90 minutes

        # Check if token has been inactive for too long
        if token.created < timezone.now() - timezone.timedelta(minutes=token_expiry_time):
            # Delete expired token
            token.delete()
            raise AuthenticationFailed('Token has expired due to inactivity')

        # Update last activity timestamp
        token.created = timezone.now()
        token.save()

        return (token.user, token)

class DeviceJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Get Authorization header
        header = get_authorization_header(request)

        # Get Device ID from header
        device_id = request.headers.get('X-Device-ID')

        if not device_id:
            return None

        try:
            # Standard JWT authentication
            validated_token = self.get_validated_token(header)

            # Additional device validation
            try:
                # Check if device exists and is active
                mobile_device = MobileDevice.objects.get(
                    device_id=device_id,
                    is_active=True
                )
            except MobileDevice.DoesNotExist:
                raise InvalidToken("Invalid or inactive device")

            # Get user from token
            user = self.get_user(validated_token)

            return (user, validated_token)

        except (InvalidToken, TokenError):
            return None

class DeviceSpecificJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Get Device ID from header
        device_id = request.headers.get('X-Device-ID')

        if not device_id:
            return None

        try:
            # Validate token
            validated_token = self.get_validated_token(
                get_authorization_header(request)
            )

            # Check device-specific token
            mobile_device = MobileDevice.objects.get(
                device_id=device_id,
                access_token=str(validated_token),
                is_active=True
            )

            # Get user from token
            user = self.get_user(validated_token)

            return (user, validated_token)

        except (MobileDevice.DoesNotExist, InvalidToken):
            return None
