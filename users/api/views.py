from rest_framework import generics

from .serializers import RegistrationSerializer


class RegistrationAPIView(generics.CreateAPIView):
    serializer_class = RegistrationSerializer
