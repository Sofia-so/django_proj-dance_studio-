from django.db import migrations


SYSTEM_GROUPS = (
    "Client",
    "Teacher",
    "Studio Admin",
)


def create_system_groups(apps, schema_editor):
    Group = apps.get_model("auth", "Group")

    for group_name in SYSTEM_GROUPS:
        Group.objects.get_or_create(name=group_name)


def reverse_system_groups(apps, schema_editor):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ("users", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(
            create_system_groups,
            reverse_system_groups,
        ),
    ]
