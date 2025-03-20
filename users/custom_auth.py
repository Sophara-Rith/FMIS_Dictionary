# users/custom_auth.py
from django.utils import timezone
from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.conf import settings

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
