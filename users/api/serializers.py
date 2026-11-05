from typing import cast

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from users.models import User
from users.services import register_user


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = (
            "email",
            "first_name",
            "last_name",
            "phone",
            "password",
            "password_confirm",
        )

    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password": "Passwords do not match."}
            )
        return attrs

    def create(self, validated_data):
        return register_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(
        write_only=True,
        trim_whitespace=False
    )

    def validate(self, attrs):
        email = attrs["email"]
        password = attrs["password"]
        user = authenticate(
            request=self.context.get("request"),
            email=email,
            password=password
        )

        if user is None or not user.is_active:
            raise serializers.ValidationError(
                {"detail": "Invalid email or password."}
            )

        user = cast(User, user)

        if not user.email_verified:
            raise serializers.ValidationError(
                {"detail": "Email address is not verified."}
            )

        attrs["user"] = user

        return attrs


class LoginResponseSerializer(serializers.Serializer):
    access = serializers.CharField(
        help_text="Access JWT. Використовується для авторизації запитів."
    )


class APIErrorSerializer(serializers.Serializer):
    detail = serializers.CharField(
        help_text="Опис помилки."
    )


class EmptySerializer(serializers.Serializer):
    pass


class MessageResponseSerializer(serializers.Serializer):
    detail = serializers.CharField()


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()


class ResetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        write_only=True,
        trim_whitespace=False
    )
    new_password_confirm = serializers.CharField(
        write_only=True,
        trim_whitespace=False
    )

    def validate(self, attrs):
        if attrs["new_password"] != attrs["new_password_confirm"]:
            raise serializers.ValidationError({
                "new_password": "Passwords do not match."
            })
        try:
            validate_password(
                attrs["new_password"],
                user=self.context["user"]
            )
        except ValidationError as exc:
            raise serializers.ValidationError({
                "new_password": exc.messages
            })

        return attrs
