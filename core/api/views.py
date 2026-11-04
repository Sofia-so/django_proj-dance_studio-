from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema

from core.api.serializers import HomeResponseSerializer


class HomeAPIView(APIView):
    @extend_schema(
        summary="Home",
        description="Returns the welcome message of Dance Studio.",
        responses={
            200: HomeResponseSerializer,
        }
    )
    def get(self, request):
        return Response({
            "message": "Welcome to Dance Studio"
        })
