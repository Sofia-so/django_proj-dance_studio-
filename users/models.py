import uuid

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from .validators import validate_phone
from .managers import UserManager


class User(AbstractUser):
    username = None
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=150)
    email = models.EmailField(unique=True)
    phone = models.CharField(
        max_length=20,
        unique=True,
        validators=[validate_phone]
    )
    email_verified = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()


class UserSession(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sessions"
    )
    created_at = models.DateTimeField(
        default=timezone.now,
        editable=False
    )
    expires_at = models.DateTimeField(editable=False)
    last_activity_at = models.DateTimeField(
        default=timezone.now
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True
    )

    class Meta:
        indexes = [
            models.Index(
                fields=["user", "revoked_at"],
                name="user_session_active_idx",
            ),
            models.Index(
                fields=["expires_at"],
                name="user_session_expiry_idx",
            ),
        ]

    def __str__(self):
        return f"Session {self.id} — {self.user.email}"

    @property
    def is_valid(self):
        return (
            self.revoked_at is None
            and timezone.now() < self.expires_at
        )
