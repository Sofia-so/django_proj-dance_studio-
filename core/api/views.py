from rest_framework.views import APIView
from rest_framework.response import Response


class HomeAPIView(APIView):
    def get(self, request):
        return Response({
            "message": "Welcome to Dance Studio"
        })
