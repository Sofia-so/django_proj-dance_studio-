from django.urls import path

from .views import (
    RegistrationAPIView,
    VerifyEmailAPIView
)

urlpatterns = [
    path(
        "/register",
        RegistrationAPIView.as_view(),
        name="register",
    ),
    path(
        "verify-email/<uid>/<token>/",
        VerifyEmailAPIView.as_view(),
        name="verify-email",
    ),
]
