from django.contrib.auth.models import AbstractUser
from django.db import models

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

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()
