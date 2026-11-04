from django.contrib.auth.models import Group
from django.db import transaction
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings

from users.models import User, UserSession
from users.tokens import (
    email_verification_token,
    generate_jwt_tokens
)


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


@transaction.atomic
def create_user_session(user: User):
    now = timezone.now()
    session = UserSession.objects.create(
        user=user,
        expires_at=now + settings.USER_SESSION_ABSOLUTE_LIFETIME,
        last_activity_at=now,
    )
    tokens = generate_jwt_tokens(user, session)
    return session, tokens


@transaction.atomic
def revoke_user_session(
    user: User,
    session_id: str,
    refresh_token: str | None = None
):
    session = (
        UserSession.objects
        .select_for_update()
        .filter(
            pk=session_id,
            user=user
        )
        .first()
    )

    if session is None:
        return False

    if session.revoked_at is None:
        session.revoked_at = timezone.now()
        session.save(update_fields=["revoked_at"])

    if refresh_token:
        try:
            refresh = RefreshToken(refresh_token)
            refresh_session_id = refresh["session_id"]
            refresh_user_id = refresh[api_settings.USER_ID_CLAIM]
            if (
                str(refresh_session_id) == str(session.pk)
                and str(refresh_user_id) == str(user.pk)
            ):
                refresh.blacklist()
        except TokenError:
            pass

    return True