from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    RegistrationAPIView,
    VerifyEmailAPIView,
    LoginAPIView
)

app_name = "users"

urlpatterns = [
    path(
        "register/",
        RegistrationAPIView.as_view(),
        name="register"
    ),
    path(
        "verify-email/<uid>/<token>/",
        VerifyEmailAPIView.as_view(),
        name="verify-email"
    ),
    path(
        "token/refresh/",
        TokenRefreshView.as_view(),
        name="token-refresh"
    ),
    path(
        "login/",
        LoginAPIView.as_view(),
        name="login"
    ),
    # path(
    #     "logout/",
    #     LogoutAPIView.as_view(),
    #     name="logout"
    # ),
]
