from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from rest_framework_simplejwt.settings import api_settings

from typing import cast
from datetime import timedelta

from users.models import User, UserSession


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        user = cast(User, user)
        return f"{user.pk}{timestamp}{user.email_verified}"


email_verification_token = EmailVerificationTokenGenerator()


def generate_jwt_tokens(user: User, session: UserSession):
    session = UserSession.objects.select_for_update().get(
        pk=session.pk,
        user=user
    )
    now = timezone.now()
    if session.revoked_at is not None:
        raise ValueError("Session has been revoked.")

    remaining_lifetime = session.expires_at - now
    if remaining_lifetime <= timedelta(0):
        raise ValueError("Session has expired.")

    refresh_lifetime = min(
        api_settings.REFRESH_TOKEN_LIFETIME,
        remaining_lifetime
    )
    refresh = RefreshToken()
    refresh[api_settings.USER_ID_CLAIM] = str(user.pk)
    refresh["session_id"] = str(session.pk)
    refresh.set_exp(
        from_time=now,
        lifetime=refresh_lifetime
    )

    access = refresh.access_token
    access_lifetime = min(
        api_settings.ACCESS_TOKEN_LIFETIME,
        remaining_lifetime
    )
    access.set_exp(
        from_time=now,
        lifetime=access_lifetime
    )
    refresh.outstand()

    return {
        "refresh": str(refresh),
        "access": str(access)
    }


password_reset_token = PasswordResetTokenGenerator()