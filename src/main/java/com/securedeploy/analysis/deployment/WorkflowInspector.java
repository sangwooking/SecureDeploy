package com.securedeploy.analysis.deployment;

import com.securedeploy.project.model.ProjectFile;
import com.securedeploy.project.coverage.CoverageRecorder;
import java.io.StringReader;
import java.util.*;
import java.util.regex.Pattern;
import org.yaml.snakeyaml.*;
import org.yaml.snakeyaml.nodes.*;

/** Bounded YAML declarations. No actions, shell, checkout or secrets are executed/read. */
public final class WorkflowInspector {
    public record ScriptScope(boolean parsed,Set<Integer> runLines,Set<Integer> usesLines) { }
    private final List<DeploymentSnapshot.Observation> observations=new ArrayList<>();
    private final Set<String> limits=new LinkedHashSet<>(List.of("WORKFLOW_DECLARATIONS_NOT_RUNNER_OR_ATTACK_PROOF","ORGANIZATION_TOKEN_SECRETS_AND_ENVIRONMENT_APPROVAL_UNKNOWN","EXTERNAL_ACTION_AND_REUSABLE_IMPLEMENTATIONS_NOT_LOADED"));
    private final long deadline=System.nanoTime()+500_000_000L;private int nodes,jobs;
    private static final Pattern INPUT=Pattern.compile("\\$\\{\\{\\s*(github\\.event\\.pull_request\\.(?:title|body)|github\\.event\\.issue\\.(?:title|body)|github\\.head_ref)\\s*}}");
    private static final Pattern SECRET=Pattern.compile("\\$\\{\\{\\s*secrets\\.[A-Za-z_][A-Za-z_0-9]*\\s*}}");
    static DeploymentSnapshot.FileResult inspect(ProjectFile file) {
        var w=new WorkflowInspector();String status="PARSED";
        try {
            if(file.lines().stream().mapToLong(s->s.length()+1L).sum()>100_000)throw new Limit();
            var root=w.parse(file);
            var events=w.events(root.get("on"));var jobs=map(root.get("jobs"));
            for(var entry:jobs.entrySet())w.job(entry.getKey(),map(entry.getValue()),root,events);
        }catch(Limit limit){status="LIMIT_EXCEEDED";w.observations.clear();w.limits.add("CONFIG_RESOURCE_LIMIT");}
        catch(RuntimeException invalid){status="PARSE_FAILED";w.observations.clear();w.limits.add("INVALID_OR_UNSUPPORTED_WORKFLOW_YAML");}
        return new DeploymentSnapshot.FileResult(CoverageRecorder.safePath(file.relativePath()),"GITHUB_ACTIONS",status,List.copyOf(w.observations),List.copyOf(w.limits));
    }
    private Map<String,Node> parse(ProjectFile file) {
        if(file.lines().stream().mapToLong(s->s.length()+1L).sum()>100_000)throw new Limit();
        var options=new LoaderOptions();options.setCodePointLimit(100_000);options.setNestingDepthLimit(32);options.setMaxAliasesForCollections(0);options.setAllowDuplicateKeys(false);
        Node node=new Yaml(options).compose(new StringReader(String.join("\n",file.lines())));
        validate(node,0,Collections.newSetFromMap(new IdentityHashMap<>()));return map(node);
    }
    public static ScriptScope scriptScope(ProjectFile file) {
        var w=new WorkflowInspector();var runs=new HashSet<Integer>();var uses=new HashSet<Integer>();
        try {
            for(var job:map(w.parse(file).get("jobs")).values()) {
                var fields=map(job);
                if(fields.containsKey("uses")){w.lines(fields.get("uses"),uses);continue;}
                if(!(fields.get("steps") instanceof SequenceNode steps))throw new IllegalArgumentException();
                for(var n:steps.getValue()){w.tick();var step=map(n);if(step.containsKey("uses"))w.lines(step.get("uses"),uses);if(step.containsKey("run"))w.lines(step.get("run"),runs);}
            }
            return new ScriptScope(true,Set.copyOf(runs),Set.copyOf(uses));
        }catch(RuntimeException unknown){return new ScriptScope(false,Set.of(),Set.of());}
    }
    private void lines(Node node,Set<Integer> result) {
        if(!(node instanceof ScalarNode))throw new IllegalArgumentException();
        int end=node.getEndMark().getLine()+(node.getEndMark().getColumn()>0?1:0);
        for(int line=node.getStartMark().getLine();line<end;line++){tick();result.add(line+1);}
    }
    private void validate(Node node,int depth,Set<Node> seen) {
        tick();if(node==null||depth>32||!seen.add(node)||!Set.of(Tag.MAP,Tag.SEQ,Tag.STR,Tag.BOOL,Tag.INT,Tag.NULL,Tag.FLOAT).contains(node.getTag()))throw new IllegalArgumentException();
        if(node instanceof MappingNode m){var names=new HashSet<String>();for(var t:m.getValue()){
            if(!(t.getKeyNode() instanceof ScalarNode k)||!(k.getTag().equals(Tag.STR)||k.getTag().equals(Tag.BOOL)&&k.getValue().equals("on"))||!names.add(k.getValue())||k.getValue().equals("<<"))throw new IllegalArgumentException();
            validate(k,depth+1,seen);validate(t.getValueNode(),depth+1,seen);
        }}else if(node instanceof SequenceNode s)for(var n:s.getValue())validate(n,depth+1,seen);
    }
    private Set<String> events(Node node) {
        var result=new HashSet<String>();
        if(node instanceof MappingNode)result.addAll(map(node).keySet());
        else if(node instanceof SequenceNode s)for(var n:s.getValue())result.add(scalar(n));
        else if(node instanceof ScalarNode)result.add(scalar(node));else limits.add("WORKFLOW_EVENTS_UNKNOWN");
        if(result.contains("workflow_run")||result.contains("workflow_call"))limits.add("WORKFLOW_EVENT_CHAIN_NOT_RESOLVED");return result;
    }
    private String permissions(Node node) {
        if(node==null)return "UNKNOWN";String value=scalar(node);
        if(value.equals("write-all"))return "WRITE";if(value.equals("read-all"))return "READ";
        if(!(node instanceof MappingNode))return "UNKNOWN";var p=map(node);boolean write=false;
        for(var e:p.entrySet()){
            if(!Set.of("actions","attestations","checks","contents","deployments","discussions","id-token","issues","models","packages","pages","pull-requests","security-events","statuses").contains(e.getKey())||!Set.of("read","write","none").contains(scalar(e.getValue())))return "UNKNOWN";
            write|=scalar(e.getValue()).equals("write");
        }return write?"WRITE":p.isEmpty()?"NONE":"READ";
    }
    private void job(String name,Map<String,Node> job,Map<String,Node> root,Set<String> events) {
        tick();jobs++;if(!name.matches("[A-Za-z_][A-Za-z_0-9-]*")){limits.add("JOB_IDENTIFIER_UNKNOWN");return;}
        String safe=ComposeInspector.safeIdentifier(name);String scope="job:"+(safe.equals("[redacted-name]")?"[redacted-job-"+jobs+"]":safe);
        if(job.containsKey("uses")){limits.add("REUSABLE_WORKFLOW_NOT_RESOLVED");return;}
        if(!(job.get("steps") instanceof SequenceNode steps)){limits.add("WORKFLOW_STEPS_UNKNOWN");return;}
        var permissionNode=job.containsKey("permissions")?job.get("permissions"):root.get("permissions");String permission=permissions(permissionNode);
        add(permissionNode,scope,"effective_permissions",!permission.equals("UNKNOWN"),permission+" declaration; effective runtime token not verified","");
        boolean jobKnown=!job.containsKey("if")&&!job.containsKey("needs")&&!job.containsKey("strategy")&&!job.containsKey("container")&&!job.containsKey("defaults")&&!root.containsKey("defaults");
        if(!jobKnown)limits.add("JOB_CONDITION_MATRIX_DEPENDENCY_OR_SHELL_UNKNOWN");
        if(scalar(job.get("if")).equals("false"))return;
        var environment=new LinkedHashMap<String,Node>();mergeEnv(environment,root.get("env"));mergeEnv(environment,job.get("env"));
        String checkout="UNKNOWN";int checkoutLine=1;boolean credential=false;int index=0;
        for(Node stepNode:steps.getValue()) {
            tick();int current=index++;var step=map(stepNode);
            if(scalar(step.get("if")).equals("false"))continue;
            boolean stepKnown=!step.containsKey("if")&&!step.containsKey("working-directory")&&!step.containsKey("shell");
            if(!stepKnown){checkout="UNKNOWN";limits.add("STEP_CONDITION_WORKSPACE_OR_SHELL_UNKNOWN");}
            var env=new LinkedHashMap<>(environment);mergeEnv(env,step.get("env"));
            boolean declaredSecret=env.values().stream().anyMatch(n->SECRET.matcher(scalar(n)).find());
            String uses=scalar(step.get("uses"));
            if(!uses.isEmpty()) {
                boolean local=uses.matches("\\./[A-Za-z0-9_./-]+")&&!Arrays.asList(uses.split("/")).contains("..");
                add(step.get("uses"),scope,local?"action_local":uses.matches("[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[a-fA-F0-9]{40}")?"action_sha":"action_ref_unverified",true,"reference declaration; action implementation not inspected","");
                if(uses.equals("actions/checkout@v4")&&stepKnown){
                    var with=step.containsKey("with")?map(step.get("with")):Map.<String,Node>of();String ref=scalar(with.get("ref")),repo=scalar(with.get("repository"));
                    boolean shape=with.keySet().stream().allMatch(k->Set.of("ref","repository","persist-credentials","fetch-depth").contains(k));
                    boolean head=ref.matches("\\$\\{\\{\\s*github\\.event\\.pull_request\\.head\\.sha\\s*}}")
                            &&(repo.isEmpty()||repo.matches("\\$\\{\\{\\s*github\\.event\\.pull_request\\.head\\.repo\\.full_name\\s*}}"));
                    checkout=shape&&head?"HEAD":shape&&ref.isEmpty()&&repo.isEmpty()?"BASE":"UNKNOWN";
                    checkoutLine=step.get("uses").getStartMark().getLine()+1;
                    String persist=scalar(with.get("persist-credentials"));credential=shape&&(persist.isEmpty()||persist.equals("true"));
                    if(!Set.of("","true","false").contains(persist))checkout="UNKNOWN";
                    add(step.get("uses"),scope,checkout.equals("BASE")?"checkout_base":checkout.equals("HEAD")?"checkout_pr_head":"checkout_unknown",!checkout.equals("UNKNOWN"),"checkout source declaration; execution not verified","");
                    continue;
                }
                if(local)execution(step.get("uses"),scope,jobKnown&&stepKnown,events,checkout,checkoutLine,credential&&permission.equals("WRITE")||declaredSecret,current);
                else {checkout="UNKNOWN";limits.add("EXTERNAL_ACTION_SIDE_EFFECTS_UNKNOWN");}
            }
            Node runNode=step.get("run");if(runNode==null)continue;String run=scalar(runNode);
            var matcher=INPUT.matcher(run);
            while(matcher.find()){
                String source=matcher.group(1);boolean available=source.contains("pull_request")||source.equals("github.head_ref")?events.contains("pull_request")||events.contains("pull_request_target"):events.contains("issues")||events.contains("issue_comment");
                if(available)add(runNode,scope,"run_expression["+current+"]",jobKnown&&stepKnown,"event-controlled expression inserted into generated shell text; runtime conditions unknown","CI_SCRIPT_EXPRESSION");
            }
            if(run.matches("(?:npm (?:ci|install|test|run [A-Za-z0-9_:-]+)|node [A-Za-z0-9_./-]+)(?: --[A-Za-z0-9_=-]+)*"))
                execution(runNode,scope,jobKnown&&stepKnown,events,checkout,checkoutLine,credential&&permission.equals("WRITE")||declaredSecret,current);
            else if(jobKnown&&stepKnown&&scalar(job.get("runs-on")).matches("ubuntu-(?:latest|[0-9.]+)")&&run.matches("printf '%s(?:\\\\n)?' \"\\$[A-Za-z_][A-Za-z0-9_]*\""))add(runNode,scope,"env_data_argument",true,"quoted environment data argument; not full shell or workflow safety","");
            else limits.add("SHELL_COMMAND_AND_ENV_FLOW_NOT_FULLY_MODELED");
        }
    }
    private void execution(Node node,String scope,boolean known,Set<String> events,String checkout,int from,boolean privilege,int index) {
        boolean risk=known&&events.contains("pull_request_target")&&checkout.equals("HEAD")&&privilege;
        add(node,scope,"project_execution["+index+"]",known,"checkout line "+from+" -> project operation declaration; token/secret runtime and approvals unknown",risk?"CI_UNTRUSTED_PR_EXECUTION":"");
        if(!risk)limits.add("PROJECT_EXECUTION_PRIVILEGE_OR_DISPATCH_NOT_PROVEN");
    }
    private void add(Node node,String scope,String setting,boolean known,String summary,String rule) {
        tick();if(observations.size()>=200)throw new Limit();
        observations.add(new DeploymentSnapshot.Observation(node==null?1:node.getStartMark().getLine()+1,scope,setting,known?"STATIC":"UNKNOWN",summary,known?rule:""));
    }
    private void tick(){if(++nodes>5000||System.nanoTime()>deadline)throw new Limit();}
    private static Map<String,Node> map(Node node){if(!(node instanceof MappingNode m))throw new IllegalArgumentException();var r=new LinkedHashMap<String,Node>();for(var p:m.getValue())r.put(((ScalarNode)p.getKeyNode()).getValue(),p.getValueNode());return r;}
    private static String scalar(Node node){return node instanceof ScalarNode s?s.getValue():"";}
    private static void mergeEnv(Map<String,Node> target,Node node){if(node!=null)target.putAll(map(node));}
    private static final class Limit extends RuntimeException { }
}
