from django.conf.urls import url
from . import views
from .viewsets import SettingsViewSet

urlpatterns = [
    url(r'^settings/config/$', views.config_view, name='config_view'),
    url(r'^settings/config$', views.config_view),
    url(r'^settings/routine/$', views.routine_view, name='routine_view'),
    url(r'^settings/routine$', views.routine_view),

    url(r'^api/v1/config/fetch/$', SettingsViewSet.as_view({'get':'config_fetch'}), name='config_fetch'),
    url(r'^api/v1/config/fetch$', SettingsViewSet.as_view({'get':'config_fetch'})),
    url(r'^api/v1/routine/$', SettingsViewSet.as_view({'get':'routine_fetch'}), name='routine_fetch'),
    url(r'^api/v1/routine$', SettingsViewSet.as_view({'get':'routine_fetch'})),
]