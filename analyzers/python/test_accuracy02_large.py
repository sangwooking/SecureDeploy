import unittest
from worker import Analyzer,MAX_FILE_CHARS,MAX_LARGE_FILE_NODES
class LargeFileTest(unittest.TestCase):
 def files(self,extra='',safe=False):
  query="c.execute('select name where id=%s',[key])" if safe else "c.execute('select name where id='+key)"
  return [{'filePath':'urls.py','content':"from django.urls import path\nfrom views import lookup\nurlpatterns=[path('records/<str:key>',lookup)]"},{'filePath':'views.py','content':'# original line\n'*7500+'from django.db import connection\ndef lookup(request,key):\n with connection.cursor() as c:\n  '+query+'\n'+extra}]
 def test_full_ast_original_lines_and_binding(self):
  for safe in [False,True]:
   a=Analyzer(self.files(safe=safe)).run();self.assertEqual('PARSED',a['files'][1]['parseStatus']);self.assertEqual('PARTIAL',a['status']);self.assertIn('LARGE_FILE_BOUNDED_REACHABLE_ANALYSIS',a['files'][1]['limitations']);self.assertEqual(0 if safe else 1,len(a['findings']))
   if not safe:self.assertEqual(7504,a['findings'][0]['sink']['line'])
 def test_dense_ast_and_char_bound_fail_closed(self):
  a=Analyzer(self.files(extra='\na=0'*7000)).run();self.assertEqual('LIMIT_EXCEEDED',a['files'][1]['parseStatus']);self.assertFalse(a['findings'])
  f=self.files();f[1]['content']='#'*(MAX_FILE_CHARS+1);a=Analyzer(f).run();self.assertEqual('LIMIT_EXCEEDED',a['files'][1]['parseStatus']);self.assertFalse(a['findings'])
 def test_unregistered_and_invalid_large_source_not_safe(self):
  f=self.files()[1:];a=Analyzer(f).run();self.assertFalse(a['findings']);self.assertEqual(0,a['files'][0]['entrypoints']);self.assertEqual('PARTIAL',a['status'])
  f[0]['content']+='\ndef broken(:';a=Analyzer(f).run();self.assertEqual('PARSE_FAILED',a['files'][0]['parseStatus'])
