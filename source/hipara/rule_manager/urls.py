from django.conf.urls import patterns, url

from . import views

urlpatterns = patterns('',

    # # Rule Pages
    # url(r'^rule/(?P<rule_id>\d+)/$', views.rule_view, name='rule_view'),

    # Search
    url(r'^search/', views.search, name='search'),
    
    # Post Data Pages
    # url(r'^update/(?P<add_type>.+)/$', views.post_data, name='post_data'),


    url(r'^export/rule/all/$', views.export_all, name='export_all'),
    url(r'^rule/(?P<rule_id>\d+)/$', views.rule_view, name='rule_view'),
    url(r'^export/rule/(?P<rule_id>\d+)/$', views.export_rule, name='export_rule'),
    url(r'^export/category/(?P<category_id>\d+)/$', views.export_category, name='export_category'),
    url(r'^import/$', views.import_rules, name='import_rules'),
)