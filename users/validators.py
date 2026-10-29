import phonenumbers
from django.core.exceptions import ValidationError


def validate_phone(value):
    try:
        phone = phonenumbers.parse(value, None)

        if not phonenumbers.is_valid_number(phone):
            raise ValidationError("Enter a valid phone number.")

    except phonenumbers.NumberParseException:
        raise ValidationError(
            "Enter a valid phone number in international format."
        )