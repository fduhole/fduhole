# Generated by Django 3.1.5 on 2021-01-26 12:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hole', '0003_auto_20210126_1143'),
    ]

    operations = [
        migrations.AlterField(
            model_name='discussion',
            name='mapping',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='discussion',
            name='tag',
            field=models.ManyToManyField(blank=True, null=True, to='hole.Tag'),
        ),
    ]
