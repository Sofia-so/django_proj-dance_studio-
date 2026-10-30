from django.contrib.auth.models import Group
from django.db import transaction
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
from django.core.mail import send_mail

from users.models import User
from users.tokens import email_verification_token


def generate_email_verification_data(user):
    uid = urlsafe_base64_encode(
        force_bytes(user.pk)
    )

    token = email_verification_token.make_token(user)

    return uid, token


def send_verification_email(user):
    uid, token = generate_email_verification_data(user)

    verification_url = (
        f"http://127.0.0.1:8000/api/auth/"
        f"verify-email/{uid}/{token}/"
    )

    send_mail(
        subject="Verify your email",
        message=(
            "Please verify your email by opening this link:\n\n"
            f"{verification_url}"
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
    )


@transaction.atomic
def register_user(**validated_data):
    password = validated_data.pop("password")
    validated_data.pop("password_confirm")

    user = User.objects.create_user(
        password=password,
        **validated_data,
    )

    client_group = Group.objects.get(name="Client")
    user.groups.add(client_group)

    send_verification_email(user)

    return user
