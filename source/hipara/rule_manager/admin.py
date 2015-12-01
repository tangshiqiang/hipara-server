from django.contrib import admin
from .models import Rule, MetaData, RuleString, Condition


admin.site.register(Rule)
admin.site.register(MetaData)
admin.site.register(RuleString)
admin.site.register(Condition)
