# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-09-09 07:28
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('alert', '0005_auto_20160909_0209'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='alert',
            name='hostName',
        ),
        migrations.RemoveField(
            model_name='alert',
            name='host_uuid',
        ),
    ]