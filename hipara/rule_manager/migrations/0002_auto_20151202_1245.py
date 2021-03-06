# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2015-12-02 12:45
from __future__ import unicode_literals
from django.db import migrations
from django.contrib.auth.models import User
from ..models import Category


def data_seeder(apps, schema_editor):
    superadmin = User.objects.all()[0]

    Category.objects.create(
        name="Hipara",
        created_by=superadmin,
        updated_by=superadmin
    )
    Category.objects.create(
        name="PhishFry",
        created_by=superadmin,
        updated_by=superadmin
    )


def data_revert(apps, schema_editors):
    from django.db import connection
    cursor = connection.cursor()
    cursor.execute('SET FOREIGN_KEY_CHECKS=0')
    cursor.execute('TRUNCATE TABLE {0}'.format(Category._meta.db_table))
    cursor.execute('SET FOREIGN_KEY_CHECKS=1')


class Migration(migrations.Migration):

    dependencies = [
        ('rule_manager', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(code=data_seeder, reverse_code=data_revert),
    ]
