from django.contrib.auth.models import Group
from django.db import transaction

from users.models import User


@transaction.atomic
def register_user(**validated_data):
    password = validated_data.pop("password")
    validated_data.pop("password_confirm")

    user = User.objects.create_user(
        password=password,
        **validated_data,
    )

    client_group = Group.objects.get(name="Client")
    user.groups.add(client_group)

    return user
