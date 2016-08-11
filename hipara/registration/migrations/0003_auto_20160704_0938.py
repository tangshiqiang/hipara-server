# -*- coding: utf-8 -*-
# Generated by Django 1.9 on 2016-07-04 09:38
from __future__ import unicode_literals
from django.db import migrations
from ..models import UserMetaData, Role
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password


def data_seeder(apps, schema_editor):
    role = Role.objects.create(name='Service')
    password = make_password('randomstring')
    serviceuser = User.objects.create(
        password=password,
        username='serviceuser',
        first_name='Service',
        last_name='User',
        email='serviceuser@hipara.org'
    )
    UserMetaData.objects.create(
        user=serviceuser,
        role=role,
        created_by=serviceuser,
        updated_by=serviceuser
    )


def data_revert(apps, schema_editors):
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('registration', '0002_auto_20151202_1245'),
    ]

    operations = [
    	migrations.RunPython(code=data_seeder, reverse_code=data_revert),
    ]
