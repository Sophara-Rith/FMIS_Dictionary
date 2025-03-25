from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.utils import timezone

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

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True, validators=[validate_fmis_email])
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)

    phone_number = models.CharField(max_length=20, null=True, blank=True)
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

    def __str__(self):
        return self.username

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser
