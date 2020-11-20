from django.urls import path

from . import views

app_name = "labs"


urlpatterns = [
    path('lab1', views.lab1, name='lab1'),
    path('lab2/string_hash', views.string_hash, name='string_hash'),
    path('lab2/file_hash', views.file_hash, name='file_hash'),
    path('lab2/integrity_check', views.integrity_check, name='integrity_check'),
]
