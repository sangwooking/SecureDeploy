"""Grade B identity-cast probes in retained public Spring controller copies."""
import argparse
from collection_cases import prepare

BASELINE='1303c7e1f2bcc5ce7f7d6a1ce2f4102abdfac420'
REGRESSION=[
    ('cast-selected','DANGEROUS','var m=new java.util.HashMap<String,Object>();m.put("selected",input);String label=(String)m.get("selected");','label',False),
    ('cast-discarded','SAFE','var m=new java.util.HashMap<String,Object>();m.put("selected",input);String label=(String)m.get("selected");label="fixed";','label',False),
    ('cast-bound','SAFE','Object value=input;String label=(String)value;','label',True),
    ('cast-opaque','UNKNOWN','String label=(String)unverified(input);','label',False),
    ('cast-null','SAFE','Object value=null;String ignored=(String)value;','"fixed"',False),
    ('cast-joined','DANGEROUS','Object value=input;String label=(String)value+"suffix";','label',False),
]
VALIDATION=[
    ('cast-request-array','DANGEROUS','Object value=benchmarkRequest.getParameterValues("q")[0];String label=(String)value;','label',False),
    ('cast-array-replaced','SAFE','Object[] values={input};String label=(String)values[0];label="constant";','label',False),
    ('cast-branch','DANGEROUS','String label=(String)input;if(benchmarkRequest.getParameter("mode")==null)label="fixed";','label',False),
    ('cast-side-effect','DANGEROUS','Object value=input;String label=(String)value+(input="fixed");','label',False),
    ('cast-unknown-map','UNKNOWN','var m=new java.util.HashMap<String,Object>();m.put("selected",unverified(input));String label=(String)m.get("selected");','label',False),
    ('cast-null-array','SAFE','Object[] values={null};String ignored=(String)values[0];','"fixed"',False),
]

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('applications');parser.add_argument('output')
    args=parser.parse_args()
    prepare(args.applications,args.output,REGRESSION,VALIDATION,BASELINE,'java-string-cast-sql-evidence')
