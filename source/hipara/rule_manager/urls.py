from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^export/$', views.export_view, name='export'),
    url(r'^import/$', views.import_view, name='import'),
    url(r'^export/rule/(?P<rule_id>\d+)/$', views.export_rule, name='export_rule'),
    url(r'^export/category/(?P<category_id>\d+)/$', views.export_category, name='export_category'),
    url(r'^rule/(?P<rule_id>\d+)/$', views.rule_view, name='rule'),
]
