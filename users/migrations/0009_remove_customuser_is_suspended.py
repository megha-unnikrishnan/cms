# Generated by Django 4.2.17 on 2024-12-16 02:40

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_customuser_is_suspended'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='is_suspended',
        ),
    ]
