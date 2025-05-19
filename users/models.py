# users/models.py
from zoneinfo import ZoneInfo
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
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')

        # Validate email domain
        validate_fmis_email(email)

        # Extract first and last name from email if not provided
        if not extra_fields.get('first_name') or not extra_fields.get('last_name'):
            email_parts = email.split('@')[0].split('.')
            if len(email_parts) >= 2:
                extra_fields['last_name'] = email_parts[0].capitalize()
                extra_fields['first_name'] = email_parts[1].capitalize()

        # Explicitly handle additional fields
        role = extra_fields.pop('role', 'USER')
        sex = extra_fields.pop('sex', '')
        username_kh = extra_fields.pop('username_kh', '')
        staff_id = extra_fields.pop('staff_id', '')
        position = extra_fields.pop('position', '')
        phone_number = extra_fields.pop('phone_number', '')

        # Create user
        user = self.model(
            username=username,
            email=self.normalize_email(email),
            role=role,
            sex=sex,
            username_kh=username_kh,
            staff_id=staff_id,
            position=position,
            phone_number=phone_number,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        # Set default values for superuser
        extra_fields.setdefault('role', 'SUPERUSER')
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        # Validate superuser attributes
        if extra_fields.get('role') != 'SUPERUSER':
            raise ValueError('Superuser must have role=SUPERUSER')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True')

        # Use create_user method to create the superuser
        return self.create_user(username, email, password, **extra_fields)

    def get_queryset(self):
        # Override default queryset to exclude soft-deleted users
        return super().get_queryset().filter(is_deleted=False)

class User(AbstractBaseUser):
    ROLE_CHOICES = (
        ('USER', 'Regular User'),
        ('ADMIN', 'Administrator'),
        ('SUPERUSER', 'Super User'),
        ('MOBILE', 'Mobile user')
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
    login_attempt = models.IntegerField(default=0)
    suspended_at = models.DateTimeField(null=True, blank=True)
    suspension_reason = models.TextField(null=True, blank=True)
    suspended_by = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='suspended_users'
    )
    unsuspended_by = models.ForeignKey(
        'self',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='unsuspended_users'
    )
    unsuspended_at = models.DateTimeField(null=True, blank=True)

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

class MobileDevice(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='mobile_devices'
    )
    device_id = models.CharField(max_length=255, unique=True)
    device_name = models.CharField(max_length=255, null=True, blank=True)
    device_type = models.CharField(max_length=100, null=True, blank=True)

    access_token = models.TextField(null=True, blank=True)
    refresh_token = models.TextField(null=True, blank=True)

    token_created_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    # Add token expiration fields
    token_expires_at = models.DateTimeField(null=True, blank=True)
    last_activity_at = models.DateTimeField(null=True, blank=True)

    def is_token_valid(self):
        """
        Check if the token is still valid
        """
        if not self.token_expires_at:
            return False

        return timezone.now() < self.token_expires_at

    def deactivate(self):
        """
        Deactivate the device
        """
        self.is_active = False
        self.save()

    def update_activity(self):
        """
        Update last activity timestamp
        """
        self.last_activity_at = timezone.now()
        self.save()

    def save(self, *args, **kwargs):
        # Ensure timestamps are in UTC+7
        utc_plus_7 = ZoneInfo("Asia/Phnom_Penh")

        if not self.token_created_at:
            self.token_created_at = timezone.now().astimezone(utc_plus_7)

        if not self.last_activity_at:
            self.last_activity_at = timezone.now().astimezone(utc_plus_7)

        super().save(*args, **kwargs)

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

class ActivityLog(models.Model):
    ACTIONS = [
        # Staging Word Actions
        ('STAGING_CREATE', 'Staging Word Created'),
        ('STAGING_UPDATE', 'Staging Word Updated'),
        ('STAGING_DELETE', 'Staging Word Deleted'),
        ('STAGING_APPROVE', 'Staging Word Approved'),
        ('STAGING_REJECT', 'Staging Word Rejected'),

        # Dictionary Word Actions
        ('DICTIONARY_CREATE', 'Dictionary Word Created'),
        ('DICTIONARY_UPDATE', 'Dictionary Word Updated'),
        ('DICTIONARY_DELETE', 'Dictionary Word Deleted'),
        ('DICTIONARY_BULK_IMPORT', 'Dictionary Bulk Import'),

        # User Actions
        ('USER_REGISTER', 'User Registered'),
        ('USER_UPDATE', 'User Updated'),
        ('USER_DELETE', 'User Deleted'),
        ('USER_LOGIN', 'User Logged In'),
        ('USER_PASSWORD_CHANGE', 'User Changed Password'),

        #Bulk Import
        ('INITIATED', 'Initiated'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('COMPLETED_WITH_ERRORS', 'Completed with Errors'),
        ('FAILED', 'Failed')
    ]

    ROLES = [
        ('USER', 'Regular User'),
        ('ADMIN', 'Administrator'),
        ('SUPERUSER', 'Super User'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='activity_logs'
    )
    username_kh = models.CharField(max_length=255, null=True, blank=True)
    action = models.CharField(max_length=255, choices=ACTIONS)
    role = models.CharField(max_length=10, choices=ROLES)
    timestamp = models.DateTimeField(auto_now_add=True)

    # Specific details about the action
    word_kh = models.CharField(max_length=255, null=True, blank=True)
    word_en = models.CharField(max_length=255, null=True, blank=True)

    # Fields for target user information
    email = models.EmailField(null=True, blank=True)
    staff_id = models.CharField(max_length=50, null=True, blank=True)
    username = models.CharField(max_length=150, null=True, blank=True)

    # Additional details as JSON
    action_details = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name = 'Activity Log'
        verbose_name_plural = 'Activity Logs'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.username_kh or self.user.username if self.user else 'Unknown'} - {self.get_action_display()} at {self.timestamp}"
