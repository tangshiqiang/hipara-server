from django.conf.urls import url
from django.contrib.auth import views as auth_views
from . import views
from .viewsets import AuthenticationViewSet
from . import forms

urlpatterns = [
    url(r'^$', views.index_view, name='index'),
    url(r'^about/$', views.about_view, name='about'),
    url(r'^apis/$', views.apis_view, name='apis'),
    url(r'^login/$', views.login_view, name='login'),
    url(r'^logout/$', views.logout_view, name='logout'),
    url(r'^change/password/$', views.change_password_view, name='change_password'),
    url(r'^invite/$', views.invite_view, name='invite'),
    url(r'^users/$', views.users_view, name='users'),
    url(r'^alerts/$', views.alert_view, name='alert'),
    url(r'^register/(?P<token>\w+)/$', views.register_view, name='register'),
    url(r'^signup/$', views.signup_view, name='signup'),
    url(r'^users/(?P<id>\w+)/$', views.users_detail_view, name='users_detail'),
    url(r'^api/v1/auth/login$', AuthenticationViewSet.as_view({'post':'login'}), name='login_api'),
    url(r'^api/v1/auth/logout$', AuthenticationViewSet.as_view({'get':'logout'}), name='logout_api'),
    url(r'^signup/$', views.signup_view, name='signup'),
    url(r'^verify/(?P<token>\w+)/$', views.verify_view, name='verify'),
    url(r'^signup$', views.signup_view),
    url(r'^verify/(?P<token>\w+)$', views.verify_view),
    url(r'^password/reset/$', auth_views.password_reset, name='password_reset'),
    url(r'^password/reset/done/$', auth_views.password_reset_done, name='password_reset_done'),
    url(r'^password/reset/confirm/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/',
        auth_views.password_reset_confirm, {'set_password_form': forms.SetPasswordForm },name='password_reset_confirm'),
    url(r'^password/reset/confirm/done/$', auth_views.password_reset_complete, name='password_reset_complete'),
]
