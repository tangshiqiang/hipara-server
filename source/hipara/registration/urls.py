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


    # url(r'^profile/update/$', views.profile_update_view, name='profile_update'),




    # # SignUp Page
    # url(r'^register/(?P<token>\w+)/$', views.register, name='register'),
    #
    # # SignUp Operation
    # url(r'^signup/(?P<token>\w+)/$', views.sign_up, name='sign_up'),
    #
    # # Index
    #
    #
    # # Login Page
    # url(r'^login/$', views.login_page, name='login'),
    #
    # # Logout Page
    # url(r'^logout/$', views.logout_page, name='logout'),
    #
    # url(r'^invites/$', views.invite_page, name='invite_page'),

]
