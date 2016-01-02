# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import datetime
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Category',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('cat_name', models.CharField(max_length=200, null=True, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Condition',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('condition', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='MetaData',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('meta_key', models.CharField(max_length=200, null=True, blank=True)),
                ('meta_value', models.CharField(max_length=200, null=True, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='Rule',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('rule_name', models.CharField(max_length=200)),
                ('rule_description', models.CharField(max_length=200, null=True, blank=True)),
                ('rule_category', models.CharField(max_length=200, null=True, blank=True)),
                ('rule_source', models.CharField(max_length=200, null=True, blank=True)),
                ('rule_version', models.IntegerField(default=0)),
                ('rule_created', models.DateTimeField(default=datetime.datetime(2015, 10, 12, 21, 11, 32, 410615, tzinfo=utc))),
                ('rule_edited', models.DateTimeField(default=datetime.datetime(2015, 10, 12, 21, 11, 32, 410653, tzinfo=utc))),
                ('rule_state', models.IntegerField(default=0)),
                ('rule_active', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='RuleStrings',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('string_type', models.CharField(default=b'text', max_length=20)),
                ('string_name', models.CharField(max_length=200)),
                ('string_value', models.CharField(max_length=1000)),
                ('string_nocase', models.BooleanField(default=False)),
                ('string_wide', models.BooleanField(default=False)),
                ('string_full', models.BooleanField(default=False)),
                ('string_ascii', models.BooleanField(default=False)),
                ('rule', models.ForeignKey(to='rule_manager.Rule')),
            ],
        ),
        migrations.AddField(
            model_name='metadata',
            name='rule',
            field=models.ForeignKey(to='rule_manager.Rule'),
        ),
        migrations.AddField(
            model_name='condition',
            name='rule',
            field=models.ForeignKey(to='rule_manager.Rule'),
        ),
    ]
