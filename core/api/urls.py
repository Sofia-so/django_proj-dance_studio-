from django.urls import path
from . import views

urlpatterns = [
    path(
        "",
        views.HomeAPIView.as_view(),
        name="api-home"
    )
]