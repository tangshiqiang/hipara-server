from django import forms
from django.contrib.auth.models import User
from django.contrib.auth import password_validation
from django.utils.translation import ugettext_lazy as _

class RegisterForm(forms.Form):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)
    email = forms.EmailField(required=True)
    password = forms.CharField(widget=forms.PasswordInput(), required=True, min_length=6, max_length=75)

    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            user = User.objects.get(email=email)
        except:
            return email
        if user.metadata.deleted_at:
            raise forms.ValidationError("This Account is Disabled contact to Admin")
        raise forms.ValidationError("This email already been registered")

class SignUpForm(forms.Form):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)    
    email = forms.EmailField(required=True)
    password = forms.CharField(widget=forms.PasswordInput(), required=True, min_length=6, max_length=75)
    job_title = forms.CharField(max_length=250, required=False)
    company = forms.CharField(max_length=250, required=False)

    def clean_email(self):
        email = self.cleaned_data['email']
        try:
            user = User.objects.get(email=email)
        except:
            return email
        if user.metadata.deleted_at:
            raise forms.ValidationError("This Account is Disabled contact to Admin")
        raise forms.ValidationError("This email already been registered")


class LoginForm(forms.Form):
    email = forms.CharField(required=True, min_length=7, max_length=75)
    password = forms.CharField(required=True, min_length=6, max_length=75)

class ChangePasswordForm(forms.Form):
    old_password = forms.CharField(widget=forms.PasswordInput(), required=True, min_length=6, max_length=75)
    new_password = forms.CharField(widget=forms.PasswordInput(), required=True, min_length=6, max_length=75)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

    def clean_old_password(self):
        old_password = self.cleaned_data['old_password']
        if self.user.check_password(old_password) :
            return old_password;
        raise forms.ValidationError("Old password isn't valid")

class UpdatePasswordForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(), required=True, min_length=6, max_length=75)
    re_password = forms.CharField(widget=forms.PasswordInput(), required=True, min_length=6, max_length=75)

    def clean_re_password(self):
        password = self.cleaned_data['password']
        re_password = self.cleaned_data['re_password']
        if password == re_password:
            return re_password;
        raise forms.ValidationError("password and retyped password does not match")

class SetPasswordForm(forms.Form):
    """
    A form that lets a user change set their password without entering the old
    password
    """
    
    
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput,
        strip=False,
        help_text=password_validation.password_validators_help_text_html(),
        min_length=6, max_length=75
    )
    new_password2 = forms.CharField(
        label=_("New password confirmation"),
        strip=False,
        widget=forms.PasswordInput,
        min_length=6, max_length=75
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(SetPasswordForm, self).__init__(*args, **kwargs)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'],
                    code='password_mismatch',
                )
        password_validation.validate_password(password2, self.user)
        return password2

    def save(self, commit=True):
        password = self.cleaned_data["new_password1"]
        self.user.set_password(password)
        if commit:
            self.user.save()
        return self.user

