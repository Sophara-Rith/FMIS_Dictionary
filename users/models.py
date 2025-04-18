# users/models.py
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.conf import settings

def validate_fmis_email(value):
    validate_email(value)
    if not value.endswith('@fmis.gov.kh'):
        raise ValidationError('Only FMIS email address is acceptant.')

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, first_name=None, last_name=None, role='USER', phone_number=None):
        if not email:
            raise ValueError('Users must have an email address')

        # Validate email domain
        validate_fmis_email(email)

        # Extract first and last name from email if not provided
        if not first_name or not last_name:
            email_parts = email.split('@')[0].split('.')
            if len(email_parts) >= 2:
                last_name = email_parts[0].capitalize()
                first_name = email_parts[1].capitalize()

        user = self.model(
            username=username,
            email=self.normalize_email(email),
            first_name=first_name,
            last_name=last_name,
            role=role,
            phone_number=phone_number
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None):
        user = self.create_user(
            username=username,
            email=email,
            password=password,
            role='SUPERUSER'
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    ROLE_CHOICES = (
        ('USER', 'Regular User'),
        ('ADMIN', 'Administrator'),
        ('SUPERUSER', 'Super User')
    )

    SEX_CHOICES = (
        ('MALE', 'Male'),
        ('FEMALE', 'Female'),
        ('OTHER', 'Other'),
        ('PREFER_NOT_TO_SAY', 'Prefer Not to Say')
    )

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True, validators=[validate_fmis_email])
    username_kh = models.CharField(max_length=150,blank=True,null=True,verbose_name='Khmer Username')
    sex = models.CharField(max_length=20, choices=SEX_CHOICES, blank=True, null=True, verbose_name='Sex')
    staff_id = models.CharField(max_length=50,unique=True,blank=True,null=True,verbose_name='Staff Identification Number')
    position = models.CharField(max_length=100,blank=True,null=True,verbose_name='Job Position')
    phone_number = models.CharField(max_length=20,blank=True,null=True,verbose_name='Phone Number')
    profile_picture = models.ImageField(upload_to='profile_pictures/',blank=True,null=True,verbose_name='Profile Picture')

    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='USER')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)

    is_suspended = models.BooleanField(default=False)
    last_login_attempt = models.DateTimeField(null=True, blank=True)
    login_attempts = models.IntegerField(default=0)
    suspended_at = models.DateTimeField(null=True, blank=True)
    suspension_reason = models.TextField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def soft_delete(self):
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser

class UserManager(BaseUserManager):
    def get_queryset(self):
        # Override default queryset to exclude soft-deleted users
        return super().get_queryset().filter(is_deleted=False)

class MobileDevice(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='mobile_devices'
    )
    device_id = models.CharField(max_length=255, unique=True)

    device_name = models.TextField(null=True, blank=True)
    device_type = models.TextField(null=True, blank=True)

    # Store individual tokens for each device
    access_token = models.TextField(null=True, blank=True)
    refresh_token = models.TextField(null=True, blank=True)

    token_created_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    def generate_device_tokens(self, user):
        """
        Generate and store unique tokens for this specific device
        """
        # Create refresh token
        refresh = RefreshToken.for_user(user)

        # Add device-specific identifier to prevent conflicts
        refresh['device_id'] = self.device_id

        # Store both access and refresh tokens
        self.access_token = str(refresh.access_token)
        self.refresh_token = str(refresh)
        self.token_created_at = timezone.now()
        self.save()

        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token
        }

    def refresh_device_tokens(self, user):
        """
        Refresh tokens for this specific device without invalidating other devices
        """
        # Create new refresh token
        refresh = RefreshToken.for_user(user)

        # Maintain device-specific identifier
        refresh['device_id'] = self.device_id

        # Update tokens
        self.access_token = str(refresh.access_token)
        self.refresh_token = str(refresh)
        self.token_created_at = timezone.now()
        self.save()

        return {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token
        }

User = get_user_model()

class UserComment(models.Model):
    """
    Model to store user comments submitted through mobile app
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='comments')
    device_id = models.CharField(max_length=255, null=True, blank=True)
    detail = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    is_reviewed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'User Comment'
        verbose_name_plural = 'User Comments'

    def __str__(self):
        return f"Comment by {self.user.username} at {self.created_at}"
