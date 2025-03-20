from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, role='USER'):
        if not email:
            raise ValueError('Users must have a email address')

        user = self.model(
            username=username,
            email=self.normalize_email(email),
            role=role
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
        ('USER', 'Data Entry User'),
        ('ADMIN', 'Administrator'),
        ('SUPERUSER', 'Super User')
    )

    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100, null=True, blank=True)
    last_name = models.CharField(max_length=100, null=True, blank=True)

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='USER')

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    # New fields for enhanced user management
    is_suspended = models.BooleanField(default=False)
    suspension_reason = models.TextField(null=True, blank=True)
    suspended_at = models.DateTimeField(null=True, blank=True)

    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)

    login_attempts = models.IntegerField(default=0)
    last_login_attempt = models.DateTimeField(null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def increment_login_attempts(self):
        self.login_attempts += 1
        self.last_login_attempt = timezone.now()

        # Suspend after 3 failed attempts
        if self.login_attempts >= 3:
            self.suspend_user(
                reason='Exceeded maximum login attempts',
                suspended_by=None
            )

        self.save()

    def reset_login_attempts(self):
        self.login_attempts = 0
        self.last_login_attempt = None
        self.save()

    def can_attempt_login(self):
        # Check if account is suspended
        if self.is_suspended:
            return False

        # If no previous attempts, allow login
        if not self.last_login_attempt:
            return True

        # Reset attempts after 15 minutes
        time_since_last_attempt = timezone.now() - self.last_login_attempt
        if time_since_last_attempt.total_seconds() > 900:  # 15 minutes
            self.reset_login_attempts()
            return True

        return self.login_attempts < 3

    def __str__(self):
        return self.username

    def suspend_user(self, reason, suspended_by):
        self.is_suspended = True
        self.suspension_reason = reason
        self.suspended_at = timezone.now()
        self.save()

    def unsuspend_user(self):
        self.is_suspended = False
        self.suspension_reason = None
        self.suspended_at = None
        self.save()

    def has_perm(self, perm, obj=None):
        return self.is_superuser or self.is_staff

    def has_module_perms(self, app_label):
        return self.is_superuser or self.is_staff
