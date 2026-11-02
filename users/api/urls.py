from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    RegistrationAPIView,
    VerifyEmailAPIView
)

urlpatterns = [
    path(
        "register/",
        RegistrationAPIView.as_view(),
        name="register",
    ),
    path(
        "verify-email/<uid>/<token>/",
        VerifyEmailAPIView.as_view(),
        name="verify-email",
    ),
    path(
        "token/refresh/",
        TokenRefreshView.as_view(),
        name="token-refresh",
    ),
]
