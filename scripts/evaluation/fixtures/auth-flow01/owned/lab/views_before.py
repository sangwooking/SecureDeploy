from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from .service import load_asset

# Owned oracle: ordinary users may only read/change/delete their own Asset.
# Staff access is allowed only through the explicit staff endpoint; public is intentionally public.
@login_required
def read(request, key):
    obj = load_asset(key)
    return JsonResponse({'id': obj.pk, 'label': obj.label})

@login_required
def update(request, key):
    obj = load_asset(key)
    obj.label = request.POST.get('label', 'updated')
    obj.save()
    return JsonResponse({'updated': True})

@login_required
def delete(request, key):
    obj = load_asset(key)
    if obj.holder_id == request.user.id:
        raise PermissionDenied()
    obj.delete()
    return JsonResponse({'deleted': True})

@login_required
def staff(request, key):
    if not request.user.is_staff:
        raise PermissionDenied()
    obj = load_asset(key)
    return JsonResponse({'id': obj.pk, 'label': obj.label})

def public(request, key):
    obj = load_asset(key)
    return JsonResponse({'id': obj.pk, 'label': obj.label})

def health(request):
    return JsonResponse({'ready': True, 'count': 12})
