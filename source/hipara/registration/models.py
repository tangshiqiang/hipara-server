from django.db import models
from django.contrib.auth.models import User
# from PIL import Image

class Role(models.Model):
    role_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=150)

    def __str__(self):
        return self.name

class UserMetaData(models.Model):
    user = models.OneToOneField(User, related_name='metadata')
    image = models.ImageField(upload_to='images/profile', blank=True, null=True)
    role = models.ForeignKey(Role, related_name='user_role', default=3)
    created_by = models.ForeignKey(User, related_name='created_users', blank=True, null=True)
    updated_by = models.ForeignKey(User, related_name='updated_users', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(default=None, blank=True, null=True)

    def __str__(self):
        return self.user.email


class User_invite_token(models.Model):
    token = models.CharField(max_length=250)
    email = models.EmailField(max_length=100, null=True, blank=True)
    expiry_date = models.DateTimeField(default=None, null=True, blank=True)
    created_by = models.ForeignKey(User, related_name='created_invite', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.token