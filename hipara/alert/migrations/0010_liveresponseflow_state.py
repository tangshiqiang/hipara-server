# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-10-16 23:18
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('alert', '0009_auto_20161015_0743'),
    ]

    operations = [
        migrations.AddField(
            model_name='liveresponseflow',
            name='state',
            field=models.IntegerField(choices=[(0, 'Running'), (1, 'Complete'), (2, 'Error'), (3, 'Canceled')], default=0),
        ),
    ]
