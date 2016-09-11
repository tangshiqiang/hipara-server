from django.conf.urls import url
from .viewsets import LogsViewSet


urlpatterns = [
    url(r'^api/v1/alerts$', LogsViewSet.as_view({'post':'store_alerts', 'get':'view_alerts'}), name='store_alerts'),
    url(r'^api/v1/alert/(?P<alert_id>\d+)/update_eval/(?P<EVAL>\d+)/$', LogsViewSet.as_view({'post': 'update_alert_eval'}), name='update_alert_eval'),
    url(r'^api/v1/logs$', LogsViewSet.as_view({'post':'store_logs'}), name='view_logs'),
	url(r'^api/v1/host/(?P<host_id>\d+)/update_lr/$', LogsViewSet.as_view({'post':'update_host_lr'}), name='update_host_lr'),
]
