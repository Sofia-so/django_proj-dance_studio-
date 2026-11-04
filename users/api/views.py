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

from users.models import User
from users.tokens import email_verification_token
from .serializers import (
    RegistrationSerializer,
    LoginSerializer,
    LoginResponseSerializer,
    APIErrorSerializer,
    EmptySerializer,
    MessageResponseSerializer
)
from users.services import (
    create_user_session,
    revoke_user_session
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
                description="Base64-encoded user ID.",
            ),
            OpenApiParameter(
                name="token",
                type=str,
                location=OpenApiParameter.PATH,
                description="Email verification token.",
            ),
        ],
        responses={
            200: MessageResponseSerializer,
            400: MessageResponseSerializer,
        }
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
                request_only=True,
            ),
            OpenApiExample(
                name="Successful login",
                value={
                    "access": "<access_token>",
                },
                response_only=True,
                status_codes=["200"],
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
