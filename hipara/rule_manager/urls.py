from django.conf.urls import url
from . import views
from . viewsets import RuleManagerViewSet


urlpatterns = [
    url(r'^export/$', views.export_view, name='export'),
    url(r'^import/$', views.import_view, name='import'),
    url(r'^export/rule/(?P<rule_id>\d+)/$', views.export_rule, name='export_rule'),
    url(r'^export/category/(?P<category_id>\d+)/$', views.export_category, name='export_category'),
    url(r'^rule/(?P<rule_id>\d+)/$', views.rule_view, name='rule'),
    url(r'^api/v1/import$', RuleManagerViewSet.as_view({'post':'import_file'}), name='import_api'),
    url(r'^api/v1/export/all$', RuleManagerViewSet.as_view({'get':'export_all'}), name='export_all_api'),
    url(r'^api/v1/export/$', RuleManagerViewSet.as_view({'get':'export_rules'}), name='export_rules_api'),
    url(r'^api/v1/export$', RuleManagerViewSet.as_view({'get':'export_rules'}), name='export_rules_api')
]
