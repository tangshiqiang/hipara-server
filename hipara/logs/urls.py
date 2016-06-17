from django.conf.urls import url
from .viewsets import LogsViewSet


urlpatterns = [
    url(r'^api/v1/logs$', LogsViewSet.as_view({'post':'store_logs', 'get':'view_logs'}), name='store_logs'),
]
