from django.conf.urls import url
from . import views


urlpatterns = [
    url(r'^$', views.index_view, name='index'),
    url(r'^about/$', views.about_view, name='about'),
    url(r'^apis/$', views.apis_view, name='apis'),
    url(r'^login/$', views.login_view, name='login'),
    url(r'^logout/$', views.logout_view, name='logout'),
    url(r'^invite/$', views.invite_view, name='invite'),
    url(r'^users/$', views.users_view, name='users'),
    url(r'^register/(?P<token>\w+)/$', views.register_view, name='register'),
    url(r'^users/(?P<id>\w+)/$', views.users_detail_view, name='users_detail'),
]