"""Source-hashed Grade B Java application copies; never executes target code."""
import argparse
from benchmark import read, write, outside, digest, validate, relative

BASELINE = '4520d11b4ebf908d2ce30da2ff54c6a3ab0c1cbf'
REGRESSION = [
    ('selected', 'DANGEROUS', 'var values=new java.util.HashMap<String,String>();values.put("a",input);', 'values.get("a")', False),
    ('unused', 'SAFE', 'var values=new java.util.HashMap<String,String>();values.put("a","fixed");values.put("b",input);', 'values.get("a")', False),
    ('alias-overwrite', 'SAFE', 'var values=new java.util.HashMap<String,String>();values.put("a",input);var alias=values;alias.put("a","fixed");', 'values.get("a")', False),
    ('late-input', 'DANGEROUS', 'var values=new java.util.HashMap<String,String>();values.put("a","fixed");values.put("a",input);', 'values.get("a")', False),
    ('binding', 'SAFE', 'String[] values=benchmarkRequest.getParameterValues("label");', 'values[0]', True),
    ('opaque', 'UNKNOWN', 'var values=new java.util.HashMap<String,String>();values.put("a","fixed");unverified(values);', 'values.get("a")', False),
]
VALIDATION = [
    ('list-selected', 'DANGEROUS', 'var values=new java.util.ArrayList<String>();values.add(input);values.add("fixed");', 'values.get(0)', False),
    ('list-replaced', 'SAFE', 'var values=new java.util.ArrayList<String>();values.add(input);values.set(0,"fixed");', 'values.get(0)', False),
    ('array-alias', 'DANGEROUS', 'String[] values={"fixed","fixed"};String[] alias=values;alias[1]=input;', 'values[1]', False),
    ('array-other', 'SAFE', 'String[] values={input,"fixed"};values[0]="constant";', 'values[1]', False),
    ('conditional', 'DANGEROUS', 'var values=new java.util.HashMap<String,String>();values.put("selected",input);if(benchmarkRequest.getParameter("mode")==null)values.put("selected","fixed");', 'values.get("selected")', False),
    ('bound-map', 'SAFE', 'var values=benchmarkRequest.getParameterMap();', 'values.get("label")[0]', True),
    ('dynamic-key', 'UNKNOWN', 'var values=new java.util.HashMap<String,String>();values.put("selected","fixed");values.put(input,"changed");', 'values.get("selected")', False),
    ('request-map', 'DANGEROUS', 'var values=benchmarkRequest.getParameterMap();', 'values.get("label")[0]', False),
]


def inject(source, signature, state, selected, bound):
    if source.count(signature) != 1:
        raise ValueError('EXACT_HANDLER_REQUIRED')
    parameters='(javax.servlet.http.HttpServletRequest benchmarkRequest, java.sql.Connection benchmarkConnection)'
    # Only the selected handler signature/body gains the controlled probe. Keep
    # original routes, annotations, remaining statements and helper references.
    changed=source.replace(signature,signature.replace('()',parameters),1)
    marker=signature.replace('()',parameters)
    insertion=changed.index(marker)+len(marker)
    block='\n        String input=benchmarkRequest.getParameter("label");\n        '+state+'\n'
    if bound:
        block+='        var benchmarkStatement=benchmarkConnection.prepareStatement("SELECT label FROM records WHERE label=?");\n'
        block+='        benchmarkStatement.setString(1,'+selected+');\n        benchmarkStatement.execute();\n'
    else:
        block+='        benchmarkConnection.prepareStatement("SELECT label FROM records WHERE label="+'+selected+').execute();\n'
    result=changed[:insertion]+block+changed[insertion:]
    line=next(i for i,l in enumerate(result.splitlines(),1) if 'benchmarkStatement.execute()' in l or 'benchmarkConnection.prepareStatement(' in l and '.execute()' in l)
    source_line=next(i for i,l in enumerate(result.splitlines(),1) if 'String input=benchmarkRequest.getParameter(' in l)
    return result,line,source_line


def source_sites(path, source):
    return [dict(filePath=path,startLine=i,endLine=i) for i,line in enumerate(source.splitlines(),1)
            if 'benchmarkRequest.getParameter' in line]


def prepare(applications, output):
    applications,output=outside(applications),outside(output)
    plan=read(applications/'application-plan.json')
    groups=[('mall','macrozheng--mall-tiny','src/main/java/com/macro/mall/tiny/modules/ums/controller/UmsResourceCategoryController.java',
             'public CommonResult<List<UmsResourceCategory>> listAll() {','LICENSE','REGRESSION',REGRESSION),
            ('clinic','spring-projects--spring-petclinic','src/main/java/org/springframework/samples/petclinic/system/WelcomeController.java',
             'public String welcome() {','LICENSE.txt','VALIDATION',VALIDATION)]
    output.mkdir(mode=0o700);(output/'cases').mkdir(mode=0o700)
    cases=[]
    for prefix,pid,path,signature,license_path,split,variants in groups:
        app=next(p for p in plan['projects'] if p['projectId']==pid)
        originals={}
        for name in [path,license_path]:
            f=applications/'sources'/pid/relative(name)
            data=f.read_bytes();receipt=next(r for r in app['files'] if r['path']==name)
            if f.is_symlink() or digest(data)!=receipt['sha256']:raise ValueError('ORIGINAL_SOURCE_HASH')
            originals[name]=data
        for name,label,state,selected,bound in variants:
            cid=prefix+'-'+name;directory=output/'cases'/cid;directory.mkdir(mode=0o700)
            source,sink,origin=inject(originals[path].decode(),signature,state,selected,bound)
            files=[]
            for filename,original in originals.items():
                data=source.encode() if filename==path else original
                target=directory/relative(filename);target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with target.open('xb') as stream:target.chmod(0o600);stream.write(data)
                files.append(dict(path=filename,sha256=digest(data),originalSha256=digest(original),controlledVariant=data!=original,
                    url='https://raw.githubusercontent.com/'+app['repositoryUrl'].removeprefix('https://github.com/')+'/'+app['commitSha']+'/'+filename,
                    urlMeaning='Original source reference; controlled probe is not upstream code.'))
            cases.append(dict(caseId=cid,grade='B',repositoryUrl=app['repositoryUrl'],repositoryCommitSha=app['commitSha'],
                repositoryGroup=app['repositoryUrl'],forkGroup=app['repositoryUrl'],vulnerabilityFamily='controlled-collection-'+prefix,
                sharedWeaknessFamily='servlet-collection-selection',language='JAVA',framework='Spring annotated controller with controlled Servlet/JDBC parameters',
                cwe='CWE-89',area='INPUT_INJECTION',license='Apache-2.0',sourceDataset='Grade B application structure, NOT an upstream vulnerability',
                groundTruthLabel=label,reviewed=True,groundTruthConfidence='CONTROLLED_STATIC_FLOW_REVIEW',evaluationSplit=split,
                targetSites=[dict(filePath=path,startLine=sink,endLine=sink)],
                sourceSites=source_sites(path,source),
                patternRules=['DANGEROUS_SQL'],flowRules=['JAVA_SQL_INPUT_FLOW'],files=files,
                labelEvidence=[app['repositoryUrl']+'/tree/'+app['commitSha']],
                sourceToSinkEvidence='Original mapped method -> inserted Servlet source -> collection selection/mutation -> inserted JDBC execution.',
                mitigationEvidence='Constant selected slot or separate SQL value binding' if label=='SAFE' else 'Selected external input' if label=='DANGEROUS' else 'Unknown mutation/key',
                labelScope='Inserted probe only; no claim about original app vulnerability or whole-project safety.',
                requiredConditions='Mapped method reached with Servlet request and usable JDBC connection. Injection/SQL runtime not executed or proven.',
                independence='Different repositories and variant forms across splits, but both apps previously observed, one curator and shared weakness; not blind or independent truth adjudication.',
                contextOmissions=['JDBC probe and parameters are controlled additions, not original application SQL or runtime wiring.','Only original mapped controller and license acquired for this evaluation; external framework/runtime/helper bodies not fully supplied.']))
    manifest=dict(schemaVersion=1,engineBaselineCommit=BASELINE,cases=cases)
    validate(manifest,output);write(output/'manifest.json',manifest)
    print(dict(cases=len(cases),grade='B',upstreamCves=0,sourceExecuted=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('applications');parser.add_argument('output')
    prepare(**vars(parser.parse_args()))
