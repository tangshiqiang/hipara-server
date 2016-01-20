from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User
from .models import UserMetaData, Role, User_invite_token


class UserProfileInline(admin.StackedInline):
    model = UserMetaData
    fk_name = 'user'
    can_delete = False


class UserAdmin(UserAdmin):
    inlines = (UserProfileInline, )

admin.site.unregister(User)
admin.site.register(User, UserAdmin)
admin.site.register(Role)
admin.site.register(User_invite_token)
