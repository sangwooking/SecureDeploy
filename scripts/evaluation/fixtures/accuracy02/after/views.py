from django.http import JsonResponse
from .service import query
def lookup(request,key):
 row=query(key)
 if row is None:
  return JsonResponse({'error':'not found'},status=404)
 return JsonResponse({'id':row[0],'label':row[1],'ready':True})
