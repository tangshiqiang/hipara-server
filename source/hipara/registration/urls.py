from django.conf.urls import url
from . import views

urlpatterns = [

    # SignUp Page
    url(r'^register/(?P<token>\w+)/$', views.register, name='register'),

    # SignUp Operation
    url(r'^signup/(?P<token>\w+)/$', views.sign_up, name='sign_up'),

    # Index
    url(r'^$', views.index_view, name='index'),

    # Login Page
    url(r'^login/$', views.login_page, name='login'),

    # Logout Page
    url(r'^logout/$', views.logout_page, name='logout'),

    url(r'^invites/$', views.invite_page, name='invite_page'),

]
