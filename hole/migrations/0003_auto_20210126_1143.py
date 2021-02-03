# Generated by Django 3.1.5 on 2021-01-26 03:43

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('hole', '0002_auto_20210126_1001'),
    ]

    operations = [
        migrations.CreateModel(
            name='Discussion',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('date_updated', models.DateTimeField(auto_now=True, db_index=True)),
                ('count', models.IntegerField()),
                ('mapping', models.JSONField()),
            ],
        ),
        migrations.CreateModel(
            name='Tag',
            fields=[
                ('name', models.CharField(max_length=191, primary_key=True, serialize=False)),
                ('count', models.IntegerField(db_index=True)),
            ],
        ),
        migrations.CreateModel(
            name='Post',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('content', models.TextField()),
                ('date_created', models.DateTimeField(auto_now_add=True)),
                ('anony_name', models.CharField(max_length=191)),
                ('reply_to', models.IntegerField(blank=True, null=True)),
                ('number', models.IntegerField()),
                ('discussion', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hole.discussion')),
            ],
        ),
        migrations.AddField(
            model_name='discussion',
            name='tag',
            field=models.ManyToManyField(to='hole.Tag'),
        ),
    ]