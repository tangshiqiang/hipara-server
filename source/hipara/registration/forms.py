from django import forms
from django.contrib.auth.models import User


class SignUpForm(forms.Form):
    first_name = forms.CharField(max_length=100, required=True)
    last_name = forms.CharField(max_length=100, required=True)
    username = forms.CharField(max_length=100, required=True)
    email = forms.EmailField(required=True)
    password = forms.CharField(widget=forms.PasswordInput(), required=True, min_length=5, max_length=75)

    def clean_username(self):
        username = self.cleaned_data['username']
        try:
            User.objects.get(username=username)
        except:
            return username
        raise forms.ValidationError("This username already been Taken")

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
    email = forms.EmailField(required=True)
    password = forms.CharField(required=True, min_length=5, max_length=75)