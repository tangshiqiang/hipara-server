from django.conf.urls import url
from . import views
from .viewsets import SettingsViewSet

urlpatterns = [
    url(r'^settings/config/$', views.config_view, name='config_view'),
    url(r'^settings/config$', views.config_view),
    url(r'^settings/routine/$', views.routine_view, name='routine_view'),
    url(r'^settings/routine$', views.routine_view),
    url(r'^settings/msi_package/$', views.msi_package_view, name='msi_package_view'),
    url(r'^settings/msi_package$', views.msi_package_view),

    url(r'^api/v1/config/fetch/$', SettingsViewSet.as_view({'get':'config_fetch'}), name='config_fetch'),
    url(r'^api/v1/config/fetch$', SettingsViewSet.as_view({'get':'config_fetch'})),
    url(r'^api/v1/routine/$', SettingsViewSet.as_view({'get':'routine_fetch'}), name='routine_fetch'),
    url(r'^api/v1/routine$', SettingsViewSet.as_view({'get':'routine_fetch'})),

    url(r'^api/v1/msi_package_build/$', SettingsViewSet.as_view({'get':'msi_package_build'}), name='msi_package_build'),
    url(r'^api/v1/msi_package_build$', SettingsViewSet.as_view({'get':'msi_package_build'})),

    url(r'^api/v1/download_msi_package/(?P<build_number>\d+)/$', SettingsViewSet.as_view({'get':'download_msi_package'}), name='download_msi_package'),
    url(r'^api/v1/download_msi_package/(?P<build_number>\d+)$', SettingsViewSet.as_view({'get':'download_msi_package'})),
]