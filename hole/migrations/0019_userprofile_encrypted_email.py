# Generated by Django 3.2 on 2021-04-26 08:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hole', '0018_userprofile'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='encrypted_email',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
