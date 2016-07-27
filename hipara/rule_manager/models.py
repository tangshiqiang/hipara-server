from django.db import models
from django.contrib.auth.models import User


class Category(models.Model):
    category_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, null=True, blank=True)
    created_by = models.ForeignKey(User, related_name='created_category', blank=True, null=True)
    updated_by = models.ForeignKey(User, related_name='updated_category', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(default=None, blank=True, null=True)

    def __str__(self):
        return self.name


class Rule(models.Model):
    rule_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=128)
    description = models.CharField(max_length=1000, null=True, blank=True)
    category = models.ForeignKey(Category, related_name='rule_category', blank=True, null=True)
    source = models.CharField(max_length=200, null=True, blank=True)
    version = models.IntegerField(default=1)
    state = models.IntegerField(default=0)
    is_active = models.BooleanField(default=True)
    status = models.NullBooleanField(default=None, null=True, blank=True)
    approved_by = models.ForeignKey(User, related_name='approved_rule', blank=True, null=True, default=None)
    created_by = models.ForeignKey(User, related_name='created_rule', blank=True, null=True)
    updated_by = models.ForeignKey(User, related_name='updated_rule', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(default=None, blank=True, null=True)
    
    def __str__(self):
        return self.name


class MetaData(models.Model):
    rule = models.ForeignKey(Rule, related_name='meta_rule', blank=True, null=True)
    key = models.CharField(max_length=200, null=True, blank=True)
    value = models.CharField(max_length=1000, null=True, blank=True)
    
    def __str__(self):
        return self.rule.name


class RuleString(models.Model):
    rule = models.ForeignKey(Rule, related_name='string_rule', blank=True, null=True)
    type = models.CharField(max_length=20, default='text')
    name = models.CharField(max_length=200)
    value = models.CharField(max_length=1000)
    is_nocase = models.BooleanField(default=False)
    is_wide = models.BooleanField(default=False)
    is_full = models.BooleanField(default=False)
    is_ascii = models.BooleanField(default=True)
    
    def __str__(self):
        return self.rule.rule_name
        

class Condition(models.Model):
    rule = models.ForeignKey(Rule, related_name='condition_rule', blank=True, null=True)
    condition = models.CharField(max_length=200)
    
    def __str__(self):
        return self.rule.rule_name
