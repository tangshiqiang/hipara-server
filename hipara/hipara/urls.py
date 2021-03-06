from django.conf.urls import include, url
from django.contrib import admin
from registration import views


urlpatterns = [
    url(r'^', include('registration.urls')),
    url(r'^', include('rule_manager.urls')),
    url(r'^', include('alert.urls')),
    url(r'^', include('settings.urls')),
    url(r'^admin/', include(admin.site.urls)),
    url('^.*$', views.not_found, name='not_found'),
]
