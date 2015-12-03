from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^search/', views.search, name='search'),
    url(r'^export/rule/all/$', views.export_all, name='export_all'),
    url(r'^rule/(?P<rule_id>\d+)/$', views.rule_view, name='rule_view'),
    url(r'^export/rule/(?P<rule_id>\d+)/$', views.export_rule, name='export_rule'),
    url(r'^export/category/(?P<category_id>\d+)/$', views.export_category, name='export_category'),
    url(r'^import/$', views.import_rules, name='import_rules'),
]
