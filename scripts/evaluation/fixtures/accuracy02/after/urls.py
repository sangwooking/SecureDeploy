from django.urls import path
from .views import lookup
urlpatterns=[path('records/<str:key>',lookup)]
