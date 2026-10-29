from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    ordering = ("email",)
    fieldsets = UserAdmin.fieldsets + (
        (
            "Additional information",
            {
                "fields": ("phone",),
            },
        ),
    )

    add_fieldsets = UserAdmin.add_fieldsets + (
        (
            "Additional information",
            {
                "fields": ("phone",),
            },
        ),
    )
