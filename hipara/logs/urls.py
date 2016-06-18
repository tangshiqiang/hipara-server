from django.conf.urls import url
from .viewsets import LogsViewSet


urlpatterns = [
    url(r'^api/v1/alerts$', LogsViewSet.as_view({'post':'store_alerts', 'get':'view_alerts'}), name='store_logs'),
]
