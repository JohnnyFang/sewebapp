import re
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext, ugettext_lazy as _


class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=False, help_text='Optional.')
    last_name = forms.CharField(max_length=30, required=False, help_text='Optional.')
    email = forms.EmailField(max_length=254, help_text='Required. Inform a valid email address.')

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2', )


class UserCreateForm(UserCreationForm):

    class Meta:
        model = User
        fields = ('username', 'password1', 'password2',)

    def __init__(self, *args, **kwargs):
        super(UserCreateForm, self).__init__(*args, **kwargs)
        self.fields['password1'].validators.append(validate_password_strength)


def validate_password_strength(value):
    """ Validates BS"""
    # check for digit
    if not any(char.isdigit() for char in value):
        raise ValidationError(_('Password must contain at least 1 digit.'))

    # check for letter
    if not any(char.isalpha() for char in value):
        raise ValidationError(_('Password must contain at least 1 letter.'))

    # check for upper case letter
    if not any(char.isupper() for char in value):
        raise ValidationError(_('Password must contain at least 1 upper case letter.'))

    # check for special char
    if not any(re.match(r'^\w+$', char) for char in value):
        raise ValidationError(_('Password must contain at least 1 special character.'))
