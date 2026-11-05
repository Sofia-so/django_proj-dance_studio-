from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone
from rest_framework.permissions import AllowAny
from drf_spectacular.utils import (
    extend_schema,
    OpenApiParameter,
    OpenApiExample,
    OpenApiResponse
)
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.views import APIView
from django.conf import settings
from django.core.exceptions import ValidationError

from users.models import User
from users.tokens import (
    email_verification_token,
    password_reset_token
)
from .serializers import (
    RegistrationSerializer,
    LoginSerializer,
    LoginResponseSerializer,
    APIErrorSerializer,
    EmptySerializer,
    MessageResponseSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer
)
from users.services import (
    create_user_session,
    revoke_user_session,
    request_password_reset,
    set_user_password,
    get_user_from_password_reset_uid
)


class RegistrationAPIView(generics.CreateAPIView):
    serializer_class = RegistrationSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        summary="User registration",
        description=(
                "Creates a new user account. "
                "An email verification message is sent after registration."
        ),
        request=RegistrationSerializer,
        responses={
            201: RegistrationSerializer,
            400: OpenApiResponse(
                description="Validation error. Invalid or missing registration data."
            ),
        },
        examples=[
            OpenApiExample(
                name="Registration request",
                description="Valid user registration data.",
                value={
                    "email": "user@example.com",
                    "first_name": "John",
                    "last_name": "Smith",
                    "phone": "+380501234567",
                    "password": "StrongPassword123!",
                    "password_confirm": "StrongPassword123!"
                },
                request_only=True
            ),
            OpenApiExample(
                name="Successful registration",
                description="The user account has been successfully created.",
                value={
                    "email": "user@example.com",
                    "first_name": "John",
                    "last_name": "Smith",
                    "phone": "+380501234567"
                },
                response_only=True,
                status_codes=["201"]
            ),
            OpenApiExample(
                name="Password mismatch",
                description="The password and password confirmation do not match.",
                value={
                    "password": "Passwords do not match."
                },
                response_only=True,
                status_codes=["400"]
            ),
            OpenApiExample(
                name="Invalid registration data",
                description="One or more required fields are missing or invalid.",
                value={
                    "email": [
                        "Enter a valid email address."
                    ]
                },
                response_only=True,
                status_codes=["400"]
            )
        ]
    )

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class VerifyEmailAPIView(generics.GenericAPIView):
    serializer_class = EmptySerializer

    @extend_schema(
        summary="Verify email address",
        description=(
                "Verifies the user's email address using "
                "the UID and token provided in the verification link."
        ),
        parameters=[
            OpenApiParameter(
                name="uid",
                type=str,
                location=OpenApiParameter.PATH,
                description="Base64-encoded user ID."
            ),
            OpenApiParameter(
                name="token",
                type=str,
                location=OpenApiParameter.PATH,
                description="Email verification token."
            ),
        ],
        responses={
            200: MessageResponseSerializer,
            400: MessageResponseSerializer,
        },
        examples=[
            OpenApiExample(
                name="Email successfully verified",
                description="The email address has been verified.",
                value={
                    "detail": "Email successfully verified."
                },
                response_only=True,
                status_codes=["200"]
            ),
            OpenApiExample(
                name="Invalid verification link",
                description="The UID or token is invalid or expired.",
                value={
                    "detail": "Invalid or expired verification link."
                },
                response_only=True,
                status_codes=["400"]
            )
        ]
    )

    def get(self, request, uid, token):
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)

        except (
                TypeError,
                ValueError,
                OverflowError,
                User.DoesNotExist
        ):
            return Response(
                {"detail": "Invalid verification link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not email_verification_token.check_token(user, token):
            return Response(
                {"detail": "Invalid or expired verification link."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.email_verified = True
        user.save(update_fields=["email_verified"])

        return Response(
            {"detail": "Email successfully verified."},
            status=status.HTTP_200_OK
        )


class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        summary="User login",
        description=(
                "Authenticates a user using email and password. "
                "Returns an Access Token in the response body and "
                "sets a Refresh Token in an HttpOnly cookie."
        ),
        request=LoginSerializer,
        responses={
            200: LoginResponseSerializer,
            400: APIErrorSerializer,
            500: APIErrorSerializer,
        },
        parameters=[
            OpenApiParameter(
                name="Set-Cookie",
                type=str,
                location=OpenApiParameter.HEADER,
                response=["200"],
                description=(
                        "Refresh Token cookie. "
                        "HttpOnly; Secure; SameSite=Lax; "
                        "Path=/api/auth/refresh/. "
                        "Max-Age is calculated from the token expiration."
                ),
            ),
        ],
        examples=[
            OpenApiExample(
                name="Login request",
                value={
                    "email": "user@example.com",
                    "password": "StrongPassword123!",
                },
                request_only=True
            ),
            OpenApiExample(
                name="Successful login",
                value={
                    "access": "<access_token>",
                },
                response_only=True,
                status_codes=["200"]
            ),
            OpenApiExample(
                name="Invalid credentials",
                value={
                    "detail": "Invalid email or password.",
                },
                response_only=True,
                status_codes=["400"],
            )
        ]
    )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        _, tokens = create_user_session(user)

        refresh_token = tokens["refresh"]
        access_token = tokens["access"]

        response = Response(
            {"access": access_token},
            status=status.HTTP_200_OK,
        )

        refresh = RefreshToken(refresh_token)
        expires_at = int(refresh["exp"])
        max_age = max(
            0,
            expires_at - int(timezone.now().timestamp()),
        )

        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            max_age=max_age,
            httponly=True,
            secure=True,
            samesite="Lax",
            path="/api/auth/refresh/"
        )

        return response


class LogoutAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="User logout",
        description=(
                "Revokes the current user session. "
                "The Refresh Token is blacklisted if it is valid "
                "and belongs to the current session. "
                "The Refresh Token cookie is deleted."
        ),
        responses={
            204: OpenApiResponse(
                description=(
                        "User successfully logged out. "
                        "The Refresh Token cookie is deleted."
                ),
            ),
            401: APIErrorSerializer
        },
        examples=[
            OpenApiExample(
                name="Successful logout",
                description="The user session is successfully revoked.",
                value=None,
                response_only=True,
                status_codes=["204"],
            ),
            OpenApiExample(
                name="Authentication error",
                description="The Access Token is missing or invalid.",
                value={
                    "detail": "Authentication credentials were not provided."
                },
                response_only=True,
                status_codes=["401"],
            ),
        ]
    )

    def post(self, request):
        access_token = request.auth

        try:
            session_id = access_token["session_id"]
        except (KeyError, TypeError):
            raise AuthenticationFailed(
                "Invalid authentication token."
            )

        refresh_token = request.COOKIES.get(
            settings.AUTH_REFRESH_COOKIE_NAME
        )
        session_revoked = revoke_user_session(
            user=request.user,
            session_id=session_id,
            refresh_token=refresh_token
        )

        if not session_revoked:
            raise AuthenticationFailed(
                "Session not found."
            )

        response = Response(
            status=status.HTTP_204_NO_CONTENT
        )
        response.delete_cookie(
            key=settings.AUTH_REFRESH_COOKIE_NAME,
            path=settings.AUTH_REFRESH_COOKIE_PATH,
            samesite=settings.AUTH_REFRESH_COOKIE_SAMESITE
        )

        return response


class ForgotPasswordAPIView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        summary="Request password reset",
        description=(
                "Request a password reset email. "
                "If an active user with a verified email address exists, "
                "a password reset link will be sent. "
                "The same response is returned regardless of whether "
                "the email address is registered."
        ),
        request=ForgotPasswordSerializer,
        responses={
            200: MessageResponseSerializer,
            400: APIErrorSerializer
        },
        examples=[
            OpenApiExample(
                name="Forgot password request",
                value={
                    "email": "user@example.com"
                },
                request_only=True
            ),
            OpenApiExample(
                name="Forgot password request successful",
                value={
                    "detail": (
                            "If an account with this email exists, "
                            "a password reset link has been sent."
                    )
                },
                response_only=True,
                status_codes=["200"]
            ),
            OpenApiExample(
                name="Invalid email",
                value={
                    "email": ["Enter a valid email address."]
                },
                response_only=True,
                status_codes=["400"]
            )
        ]
    )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        request_password_reset(
            email=serializer.validated_data["email"]
        )

        return Response(
            {
                "detail": (
                    "If an account with this email exists, "
                    "a password reset link has been sent."
                )
            },
            status=status.HTTP_200_OK
        )


class ResetPasswordAPIView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    @extend_schema(
        summary="Reset user password",
        description=(
                "Reset the user's password using a valid password reset link. "
                "The link contains a user UID and a password reset token. "
                "The new password must satisfy the configured password "
                "validation rules and match the confirmation password. "
                "After a successful reset, all active user sessions "
                "are revoked."
        ),
        request=ResetPasswordSerializer,
        responses={
            200: MessageResponseSerializer,
            400: APIErrorSerializer
        },
        examples=[
            OpenApiExample(
                name="Reset password request",
                value={
                    "new_password": "NewSecurePassword123!",
                    "new_password_confirm": "NewSecurePassword123!"
                },
                request_only=True
            ),
            OpenApiExample(
                name="Password reset successful",
                value={
                    "detail": "Password has been reset successfully."
                },
                response_only=True,
                status_codes=["200"]
            ),
            OpenApiExample(
                name="Invalid or expired reset link",
                value={
                    "new_password": [
                        "This password is too short."
                    ]
                },
                response_only=True,
                status_codes=["400"]
            )
        ]
    )

    def post(self, request, uid, token, *args, **kwargs):
        user = get_user_from_password_reset_uid(uid)

        if (
            user is None
            or not user.is_active
            or not user.email_verified
            or not password_reset_token.check_token(user, token)
        ):
            raise ValidationError({
                "detail": "Invalid or expired password reset link."
            })

        serializer = self.get_serializer(
            data=request.data,
            context={
                **self.get_serializer_context(),
                "user": user
            }
        )
        serializer.is_valid(raise_exception=True)
        set_user_password(
            user=user,
            new_password=serializer.validated_data["new_password"]
        )

        return Response(
            {"detail": "Password has been reset successfully."},
            status=status.HTTP_200_OK
        )
