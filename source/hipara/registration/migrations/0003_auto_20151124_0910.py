# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('registration', '0002_auto_20151102_1410'),
    ]

    operations = [
        migrations.AlterField(
            model_name='usermetadata',
            name='user',
            field=models.OneToOneField(to=settings.AUTH_USER_MODEL, related_name='metadata'),
        ),
    ]
