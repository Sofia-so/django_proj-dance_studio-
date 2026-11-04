from rest_framework import serializers


class HomeResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
