import unittest
from benchmark import inspection


class EntryContextAccountingTest(unittest.TestCase):
    def test_successful_parse_does_not_hide_flow_budget_exhaustion(self):
        case={'files':[{'path':'server.ts'}],'language':'TYPESCRIPT','patternRules':[]}
        file={'filePath':'server.ts','parseStatus':'PARSED','entrypoints':0,'limitations':['ANALYSIS_BUDGET_EXCEEDED']}
        row={'coverage':{'entries':[{'filePath':'server.ts','status':'SELECTED'}]},'typescript':{'status':'PARTIAL','files':[file]}}
        self.assertEqual(inspection(case,row,'ast'),'RESOURCE_LIMIT')
        self.assertEqual(inspection(case,row,'finalUser'),'RESOURCE_LIMIT')
        file['limitations']=[]
        self.assertEqual(inspection(case,row,'ast'),'NOT_SUPPORTED')
        file['entrypoints']=1
        self.assertEqual(inspection(case,row,'ast'),'UNKNOWN')


if __name__=='__main__':unittest.main()
