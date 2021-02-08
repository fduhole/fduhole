# Generated by Django 3.1.6 on 2021-02-06 07:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hole', '0011_auto_20210128_2222'),
    ]

    operations = [
        migrations.AddField(
            model_name='tag',
            name='color',
            field=models.CharField(default='blue', max_length=32),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='tag',
            name='name',
            field=models.CharField(max_length=32, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='tempuser',
            name='email',
            field=models.EmailField(max_length=32, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='tempuser',
            name='password',
            field=models.CharField(max_length=32),
        ),
        migrations.AlterField(
            model_name='tempuser',
            name='username',
            field=models.CharField(max_length=32),
        ),
    ]