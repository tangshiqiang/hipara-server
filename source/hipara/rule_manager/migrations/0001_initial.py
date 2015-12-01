# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('category_id', models.AutoField(serialize=False, primary_key=True)),
                ('name', models.CharField(max_length=200, blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('deleted_at', models.DateTimeField(blank=True, null=True, default=None)),
                ('created_by', models.ForeignKey(blank=True, related_name='created_category', to=settings.AUTH_USER_MODEL, null=True)),
                ('updated_by', models.ForeignKey(blank=True, related_name='updated_category', to=settings.AUTH_USER_MODEL, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Condition',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('condition', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='MetaData',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('key', models.CharField(max_length=200, blank=True, null=True)),
                ('value', models.CharField(max_length=200, blank=True, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='Rule',
            fields=[
                ('rule_id', models.AutoField(serialize=False, primary_key=True)),
                ('name', models.CharField(max_length=200)),
                ('description', models.CharField(max_length=200, blank=True, null=True)),
                ('source', models.CharField(max_length=200, blank=True, null=True)),
                ('version', models.IntegerField(default=0)),
                ('state', models.IntegerField(default=0)),
                ('is_active', models.BooleanField(default=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('deleted_at', models.DateTimeField(blank=True, null=True, default=None)),
                ('category', models.ForeignKey(blank=True, related_name='rule_category', to='rule_manager.Category', null=True)),
                ('created_by', models.ForeignKey(blank=True, related_name='created_rule', to=settings.AUTH_USER_MODEL, null=True)),
                ('updated_by', models.ForeignKey(blank=True, related_name='updated_rule', to=settings.AUTH_USER_MODEL, null=True)),
            ],
        ),
        migrations.CreateModel(
            name='RuleString',
            fields=[
                ('id', models.AutoField(serialize=False, primary_key=True, auto_created=True, verbose_name='ID')),
                ('type', models.CharField(max_length=20, default='text')),
                ('name', models.CharField(max_length=200)),
                ('value', models.CharField(max_length=1000)),
                ('is_nocase', models.BooleanField(default=False)),
                ('is_wide', models.BooleanField(default=False)),
                ('is_full', models.BooleanField(default=False)),
                ('is_ascii', models.BooleanField(default=False)),
                ('rule', models.ForeignKey(blank=True, related_name='string_rule', to='rule_manager.Rule', null=True)),
            ],
        ),
        migrations.AddField(
            model_name='metadata',
            name='rule',
            field=models.ForeignKey(blank=True, related_name='meta_rule', to='rule_manager.Rule', null=True),
        ),
        migrations.AddField(
            model_name='condition',
            name='rule',
            field=models.ForeignKey(blank=True, related_name='condition_rule', to='rule_manager.Rule', null=True),
        ),
    ]
