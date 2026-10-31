// Review evidence only: output context is not a new confirmed Finding Rule.
// No target execution, template engine execution or sanitizer-name trust.
export function htmlResponses({loc,append,result,note}) {
  const mime=v=>typeof v?.constant==='string'&&!v.unknown
    ? /^(?:text\/html|application\/xhtml\+xml)(?:\s*;|$)/i.test(v.constant)?'HTML'
      : /^text\/plain(?:\s*;|$)/i.test(v.constant)?'PLAIN':'OTHER' : 'UNKNOWN';
  function header(receiver,args,method,state){
    let mode='UNKNOWN';
    if(method==='type'&&args.length===1)mode=args[0]?.constant==='html'?'HTML':args[0]?.constant==='text'?'PLAIN':mime(args[0]);
    else if(args.length===2&&typeof args[0]?.constant==='string'&&args[0].constant.toLowerCase()==='content-type')mode=mime(args[1]);
    else if(args.length===2&&typeof args[0]?.constant==='string')return receiver;
    // Never mutate a shared heap receiver: branch-local vars get fresh metadata.
    const updated={...receiver,htmlResponseType:mode};
    for(const [key,v] of state.vars)if(v===receiver||receiver.ref&&v.ref===receiver.ref)state.vars.set(key,updated);
    return updated;
  }
  function observe(v,node,state,mode,method){
    if(state.context.setup)return;
    const all=[];let remaining=128;const seen=new Set();
    const collect=(x,depth)=>{if(!x||depth>3||remaining--<=0||seen.has(x.ref??x))return;seen.add(x.ref??x);all.push(...(x.trace??[]));for(const child of x.ref?.properties?.values()??[])collect(child,depth+1);};
    collect(v,0);
    const trace=all.filter(l=>/^(?:EXPRESS_|NEXT_PAGES_|QUERY_PARAMETER|REQUEST_BODY|REQUEST_HEADER)/.test(l.kind));
    if(!trace.length)return;
    if(mode==='PLAIN'||method==='json'||method==='redirect')return;
    const stringKnown=typeof v.constant==='string'||v.htmlString===true;
    const definite=method!=='render'&&(mode==='HTML'||method==='send'&&mode===undefined&&stringKnown)
      &&!v.unknown&&!v.ref&&!state.uncertain&&remaining>0;
    const location=loc(node,state.mod,'HTTP_HTML_RESPONSE',state.fn);
    append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:definite?'HTML_RESPONSE_INPUT_CANDIDATE':'HTML_RESPONSE_CONTEXT_UNKNOWN',
      operation:method,location,trace:trace.slice(0,19),limitations:[
        'REVIEW_REQUIRED_NOT_CONFIRMED_XSS','HTML_EXECUTION_AND_CLIENT_CONTEXT_NOT_VERIFIED',
        'OUTPUT_ENCODING_AND_EXTERNAL_SANITIZER_POLICY_NOT_VERIFIED',
        ...(definite?[]:['CONTENT_TYPE_TEMPLATE_OR_VALUE_FLOW_UNRESOLVED'])]},state.mod);
    note(state.mod,definite?'HTML_RESPONSE_INPUT_REVIEW_REQUIRED':'HTML_RESPONSE_CONTEXT_UNRESOLVED');
  }
  function response(v,options,node,state){
    const headers=options?.ref?.properties.get('headers');
    const entries=[...(headers?.ref?.properties??[])].filter(([k])=>k.toLowerCase()==='content-type');
    observe(v,node,state,entries.length===1?mime(entries[0][1]):headers?'UNKNOWN':'PLAIN','Response');
  }
  return {header,observe,response};
}
