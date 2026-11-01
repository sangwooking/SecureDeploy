from django.core.exceptions import PermissionDenied

def ensure_owner(item, actor):
    if item.holder_id != actor.id:
        raise PermissionDenied()
