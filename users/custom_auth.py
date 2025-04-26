# users/custom_auth.py
from venv import logger
from zoneinfo import ZoneInfo
from datetime import datetime
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
        try:
            # Get Authorization header
            header = get_authorization_header(request)

            # Get Device ID from header
            device_id = request.headers.get('X-Device-ID')

            if not device_id:
                return None

            # Find the corresponding mobile device
            try:
                mobile_device = MobileDevice.objects.get(
                    device_id=device_id,
                    is_active=True
                )
            except MobileDevice.DoesNotExist:
                raise InvalidToken("Invalid or inactive device")

            # Check if token has expired
            from zoneinfo import ZoneInfo
            from datetime import datetime

            current_time = datetime.now(ZoneInfo("Asia/Phnom_Penh"))

            if (mobile_device.token_expires_at and
                current_time > mobile_device.token_expires_at):
                # Deactivate the device
                mobile_device.is_active = False
                mobile_device.save()

                raise InvalidToken("Token has expired. Please log in again.")

            # Validate token
            validated_token = self.get_validated_token(header)

            # Get user from token
            user = self.get_user(validated_token)

            return (user, validated_token)

        except (InvalidToken, TokenError):
            return None

class MobileDeviceJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        # Only authenticate mobile endpoints
        if not self.is_mobile_endpoint(request):
            return None

        # Get Authorization header
        header = get_authorization_header(request)
        if not header:
            return None

        # Get Device ID from header
        device_id = request.headers.get('X-Device-ID')
        if not device_id:
            logger.warning("Mobile authentication attempt without Device ID")
            return None

        try:
            # Extract raw token
            try:
                raw_token = header.decode('utf-8').split()[1]
            except (IndexError, UnicodeDecodeError):
                raise InvalidToken("Invalid token format")

            # Get the mobile device
            from .models import MobileDevice
            try:
                mobile_device = MobileDevice.objects.get(
                    device_id=device_id,
                    is_active=True
                )
            except MobileDevice.DoesNotExist:
                logger.warning(f"No active mobile device found for ID: {device_id}")
                raise InvalidToken("Invalid or inactive device")

            # CRITICAL: Force expiration check with current time
            utc_plus_7 = ZoneInfo("Asia/Phnom_Penh")
            current_time = datetime.now(utc_plus_7)

            # Log times for debugging
            logger.info(f"Current time: {current_time.isoformat()}")
            logger.info(f"Token expires at: {mobile_device.token_expires_at.isoformat()}")

            # Strict expiration check
            if mobile_device.token_expires_at and current_time > mobile_device.token_expires_at:
                # Deactivate device and force token invalidation
                mobile_device.is_active = False
                mobile_device.save()

                # Log expiration
                logger.warning(f"Token expired for device {device_id}. Current: {current_time}, Expires: {mobile_device.token_expires_at}")

                # Force authentication failure
                raise AuthenticationFailed("Token has expired. Please log in again.")

            # Standard token validation
            validated_token = self.get_validated_token(raw_token)

            # Get user from token
            user = self.get_user(validated_token)

            # Update last activity
            mobile_device.last_activity_at = current_time
            mobile_device.save()

            return (user, validated_token)

        except (InvalidToken, TokenError, AuthenticationFailed) as e:
            logger.error(f"Mobile authentication error: {str(e)}")
            # Re-raise AuthenticationFailed to ensure it's properly handled
            if isinstance(e, AuthenticationFailed):
                raise e
            return None

    def is_mobile_endpoint(self, request):
        # List mobile-specific endpoints
        mobile_endpoints = [
            '/dictionary/bookmarks/',
            '/dictionary/sync',
            '/dictionary/sync_all',
            '/users/mobile/login/',
        ]

        # Check if current request path matches mobile endpoints
        return any(endpoint in request.path for endpoint in mobile_endpoints)

    def get_validated_token(self, raw_token):
        """
        Override to use custom validation logic
        """
        try:
            # Validate token using parent method
            validated_token = super().get_validated_token(raw_token)
            return validated_token
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            raise InvalidToken(str(e))

    def validate_mobile_device(self, device_id):
        from .models import MobileDevice

        try:
            mobile_device = MobileDevice.objects.get(
                device_id=device_id,
                is_active=True
            )

            # Additional device validation
            current_time = timezone.now()

            # Check if device token has expired
            if (mobile_device.token_expires_at and
                current_time > mobile_device.token_expires_at):
                # Deactivate the device
                mobile_device.is_active = False
                mobile_device.save()
                raise InvalidToken("Device token has expired")

            # Update last activity
            mobile_device.last_activity_at = current_time
            mobile_device.save()

        except MobileDevice.DoesNotExist:
            raise InvalidToken("Invalid or inactive mobile device")
