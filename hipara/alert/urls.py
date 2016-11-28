from django.conf.urls import url
from .viewsets import LogsViewSet
from .views import alert_instance, download_alert_file


urlpatterns = [
	url(r'^api/v1/alerts$', LogsViewSet.as_view({'post':'store_alerts', 'get':'view_alerts'}), name='store_alerts'),
	url(r'^api/v1/alert/(?P<alert_id>\d+)/update_eval/(?P<EVAL>\d+)/$', LogsViewSet.as_view({'post': 'update_alert_eval'}), name='update_alert_eval'),
	url(r'^api/v1/logs$', LogsViewSet.as_view({'post':'store_logs'}), name='view_logs'),
	url(r'^api/v1/host/(?P<host_id>\d+)/update_lr/$', LogsViewSet.as_view({'post':'update_host_lr'}), name='update_host_lr'),
	url(r'^api/v1/host/(?P<host_id>\d+)/$', LogsViewSet.as_view({'get': 'view_host'}), name='view_host'),
	url(r'^alert/(?P<alert_id>\d+)/$', alert_instance, name='alert'),
	url(r'api/v1/lr/(?P<lr_id>\d+)/$', LogsViewSet.as_view({'get': 'view_lr'}), name='view_lr'),
	url(r'download/alert/file/(?P<client_id>\C.\w+)/(?P<flow_id>\F:\w+)/$', download_alert_file, name="download_alert_file"),
	url(r'api/v1/alert/(?P<alert_id>\d+)/get_alert_file_status/$', LogsViewSet.as_view({'get': 'get_alert_file_status'}), name='get_alert_file_status'),
	url(r'api/v1/client/(?P<client_id>\C.\w+)/flow/(?P<flow_id>\F:\w+)/result/$', LogsViewSet.as_view({'get': 'get_flow_result'}), name='get_flow_result')
]
