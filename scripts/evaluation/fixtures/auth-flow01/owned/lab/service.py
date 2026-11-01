from django.shortcuts import get_object_or_404
from .models import Asset

def load_asset(key):
    return get_object_or_404(Asset, pk=key)
