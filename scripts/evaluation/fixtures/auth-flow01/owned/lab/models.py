from django.db import models
from django.conf import settings
class Asset(models.Model):
    holder = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    label = models.CharField(max_length=80)
