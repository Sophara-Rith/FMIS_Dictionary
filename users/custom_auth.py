# users/custom_auth.py
from django.utils import timezone
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import TokenAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken
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
        # Check if this is a mobile-specific endpoint
        is_mobile_endpoint = self.is_mobile_endpoint(request)

        if not is_mobile_endpoint:
            return None

        # Get Device ID from header
        device_id = request.headers.get('X-Device-ID')

        try:
            # Get the raw token from Authorization header
            auth_header = get_authorization_header(request)

            # Check if Authorization header is empty
            if not auth_header:
                # For mobile login endpoint, allow authentication without token
                if request.path.endswith('/users/mobile/login/'):
                    return None
                raise InvalidToken("No authorization token provided")

            # Split and decode the token
            try:
                raw_token = auth_header.decode('utf-8').split()

                # Ensure token exists and is in correct format
                if len(raw_token) < 2:
                    raise InvalidToken("Invalid authorization header format")

                raw_token = raw_token[1]  # Get the actual token part
            except (IndexError, UnicodeDecodeError) as e:
                raise InvalidToken(f"Token parsing error: {str(e)}")

            # Use mobile-specific token validation
            validated_token = self.validate_mobile_token(raw_token)

            # Additional device validation
            if device_id:
                self.validate_mobile_device(device_id)

            # Get user from token
            user = self.get_user(validated_token)

            return (user, validated_token)

        except (InvalidToken, TokenError) as e:
            print(f"Mobile Token Authentication Error: {str(e)}")
            return None

    def is_mobile_endpoint(self, request):
        # List mobile-specific endpoints
        mobile_endpoints = [
            '/dictionary/bookmarks/',
            '/dictionary/sync/',
            '/dictionary/sync_all/',
            '/users/mobile/login/',
        ]

        # Check if current request path matches mobile endpoints
        return any(endpoint in request.path for endpoint in mobile_endpoints)

    def validate_mobile_token(self, raw_token):
        # Use mobile-specific token settings
        from rest_framework_simplejwt.settings import api_settings

        # Temporarily override token settings for mobile
        original_settings = {
            'ACCESS_TOKEN_LIFETIME': api_settings.ACCESS_TOKEN_LIFETIME,
            'REFRESH_TOKEN_LIFETIME': api_settings.REFRESH_TOKEN_LIFETIME,
        }

        try:
            # Apply mobile-specific settings
            api_settings.ACCESS_TOKEN_LIFETIME = settings.MOBILE_JWT_SETTINGS['ACCESS_TOKEN_LIFETIME']
            api_settings.REFRESH_TOKEN_LIFETIME = settings.MOBILE_JWT_SETTINGS['REFRESH_TOKEN_LIFETIME']

            # Validate token
            return AccessToken(raw_token)
        finally:
            # Restore original settings
            api_settings.ACCESS_TOKEN_LIFETIME = original_settings['ACCESS_TOKEN_LIFETIME']
            api_settings.REFRESH_TOKEN_LIFETIME = original_settings['REFRESH_TOKEN_LIFETIME']

    def validate_mobile_device(self, device_id):
        from .models import MobileDevice

        try:
            MobileDevice.objects.get(
                device_id=device_id,
                is_active=True
            )
        except MobileDevice.DoesNotExist:
            raise InvalidToken("Invalid or inactive mobile device")
