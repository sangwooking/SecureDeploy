import {rawHtmlTextInputs} from './html-text-proof.mjs';
import {outputContexts,encodeReplace} from './html-context.mjs';
import ts from 'typescript';
// Review contexts and a separate, narrower HTML_TEXT_INPUT_FLOW proof contract.
// No target execution, template engine execution or sanitizer-name trust.
export function htmlResponses({loc,append,result,note,modules}) {
  const mime=v=>typeof v?.constant==='string'&&!v.unknown
    ? /^(?:text\/html|application\/xhtml\+xml)(?:\s*;|$)/i.test(v.constant)?'HTML'
      : /^application\/(?:[\w.-]+\+)?json(?:\s*;|$)/i.test(v.constant)?'JSON'
      : /^text\/plain(?:\s*;|$)/i.test(v.constant)?'PLAIN':'OTHER' : 'UNKNOWN';
  function header(receiver,args,method,state,node){
    let mode='UNKNOWN';
    // Express set/header has an object overload. Only direct inert string maps
    // are summarized: no alias, getter, spread, computed key or coercion effects.
    if(receiver.tag==='express-response'&&['set','header'].includes(method)&&args.length===1){
      const syntax=node?.arguments?.[0],map=args[0];
      const inert=syntax&&ts.isObjectLiteralExpression(syntax)&&syntax.properties.length<=16
        &&syntax.properties.every(p=>ts.isPropertyAssignment(p)
          &&(ts.isIdentifier(p.name)||ts.isStringLiteral(p.name))&&ts.isStringLiteralLike(p.initializer)
          &&!['__proto__','prototype','constructor'].includes(p.name.text.toLowerCase()));
      if(inert&&map?.ref&&!map.unknown&&!map.ref.unknown&&map.ref.properties.size===syntax.properties.length){
        const entries=[...map.ref.properties];
        if(entries.every(([,v])=>!v.unknown&&!v.ref&&typeof v.constant==='string')){
          const contentTypes=entries.filter(([k])=>k.toLowerCase()==='content-type');
          if(contentTypes.length===0)return receiver;
          if(contentTypes.length===1)return header(receiver,[{constant:'Content-Type'},contentTypes[0][1]],'set',state);
        }
      }
    }
    if(method==='type'&&args.length===1)mode=args[0]?.constant==='html'?'HTML':args[0]?.constant==='text'?'PLAIN':args[0]?.constant==='json'?'JSON':mime(args[0]);
    else if(args.length===2&&typeof args[0]?.constant==='string'&&args[0].constant.toLowerCase()==='content-type')mode=mime(args[1]);
    else if(args.length===2&&typeof args[0]?.constant==='string')return receiver;
    // Never mutate a shared heap receiver: branch-local vars get fresh metadata.
    const declared=args.length===1?args[0]?.constant:args[1]?.constant;
    const updated={...receiver,htmlResponseType:mode,htmlTextMime:declared==='html'||typeof declared==='string'&&/^text\/html(?:\s*;|$)/i.test(declared)};
    for(const [key,v] of state.vars)if(v===receiver||receiver.ref&&v.ref===receiver.ref)state.vars.set(key,updated);
    return updated;
  }
  function observe(v,node,state,mode,method,proof=false){
    if(state.context.setup)return;
    const all=[];let remaining=128;const seen=new Set();
    const collect=(x,depth)=>{if(!x||depth>3||remaining--<=0||seen.has(x.ref??x))return;seen.add(x.ref??x);all.push(...(x.trace??[]));for(const child of x.ref?.properties?.values()??[])collect(child,depth+1);};
    collect(v,0);
    const trace=all.filter(l=>/^(?:EXPRESS_|NEXT_PAGES_|QUERY_PARAMETER|REQUEST_BODY|REQUEST_HEADER)/.test(l.kind));
    if(!trace.length)return;
    if(mode==='PLAIN'||mode==='JSON'||method==='json'||method==='redirect')return;
    const stringKnown=typeof v.constant==='string'||v.htmlString===true;
    const definite=method!=='render'&&(mode==='HTML'||method==='send'&&mode===undefined&&stringKnown)
      &&!v.unknown&&!v.ref&&!state.uncertain&&remaining>0;
    const location=loc(node,state.mod,'HTTP_HTML_RESPONSE',state.fn);
    const contexts=definite?outputContexts(v):[];
    const encoded=contexts.length>0&&contexts.every(c=>c.encoded);
    const contextTrace=contexts.slice(0,4).flatMap(c=>[{...location,kind:'HTML_OUTPUT_CONTEXT_'+c.context},...(c.encoded?[{...location,kind:'VERIFIED_FIVE_ENTITY_ENCODING'}]:[])]);
    append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind:encoded?'HTML_RESPONSE_ENCODED_TEXT_EVIDENCE':definite?'HTML_RESPONSE_INPUT_CANDIDATE':'HTML_RESPONSE_CONTEXT_UNKNOWN',
      operation:method,location,trace:[...trace.slice(0,8),...(state.context.checks??[]).filter(x=>x.kind.includes('REGISTRATION')).slice(0,1),state.context.entry,...(v.htmlFlow??[]).slice(0,4),...contextTrace].filter(Boolean).slice(0,20),limitations:[
        'REVIEW_REQUIRED_NOT_CONFIRMED_XSS','HTML_EXECUTION_AND_CLIENT_CONTEXT_NOT_VERIFIED',
        encoded?'LOCAL_FIVE_ENTITY_ENCODING_ONLY_NOT_WHOLE_RESPONSE_ASSURANCE':'OUTPUT_ENCODING_AND_EXTERNAL_SANITIZER_POLICY_NOT_VERIFIED',
        ...(contexts.some(c=>c.context==='UNKNOWN')?['HTML_OUTPUT_CONTEXT_UNRESOLVED']:[]),
        ...(definite?[]:['CONTENT_TYPE_TEMPLATE_OR_VALUE_FLOW_UNRESOLVED'])]},state.mod);
    note(state.mod,definite?'HTML_RESPONSE_INPUT_REVIEW_REQUIRED':'HTML_RESPONSE_CONTEXT_UNRESOLVED');
    if(proof&&definite&&!state.context.htmlOpaqueCall&&!state.context.unresolved&&!state.context.defenses?.length&&!state.context.checks?.some(t=>t.kind==='CONDITIONAL_CHECK')){
      const endpoint=state.context.htmlEndpoint??state.context.entry?.kind;
      if(typeof endpoint!=='string'||endpoint.length>200){note(state.mod,'HTML_ENDPOINT_PROOF_UNRESOLVED');return;}
      const inputs=rawHtmlTextInputs(v).filter(p=>p.trace.some(t=>/^(?:EXPRESS_(?:QUERY|BODY|PARAMS|HEADERS)|NEXT_PAGES_(?:QUERY|BODY|HEADERS)|QUERY_PARAMETER|REQUEST_BODY|REQUEST_HEADER)$/.test(t.kind)));
      if(inputs.length){
        const source=inputs[0].trace.find(t=>/^(?:EXPRESS_(?:QUERY|BODY|PARAMS|HEADERS)|NEXT_PAGES_(?:QUERY|BODY|HEADERS)|QUERY_PARAMETER|REQUEST_BODY|REQUEST_HEADER)$/.test(t.kind));
        const entry=state.context.entry,transfer=inputs[0].trace;
        if(transfer.length>10||(v.htmlFlow??[]).length>4){note(state.mod,'HTML_TRANSFER_PROOF_LIMIT');return;}
        const flow=[...transfer,entry,...(state.context.checks??[]).filter(t=>t.kind==='EXPRESS_REGISTRATION').slice(0,1),...(v.htmlFlow??[]).slice(0,4),{...location,kind:'HTML_RESPONSE_MIME_CONFIRMED'},{...location,kind:'HTML_OUTPUT_CONTEXT_HTML_TEXT'},{...location,kind:'RAW_REQUEST_HTML_TEXT_NO_ENCODING'},location].filter(Boolean);
        if(flow.length<=20&&!result.findings.some(f=>f.ruleId==='HTTP_HTML_INPUT_FLOW'&&JSON.stringify(f.sink)===JSON.stringify(location))){
          const limits=['STATIC_HTML_TEXT_FLOW_NOT_BROWSER_EXPLOIT_PROOF','MIDDLEWARE_CSP_AND_RUNTIME_NOT_VERIFIED','HTML_ATTRIBUTES_SCRIPT_URL_CSS_NOT_COVERED'];
          const witness={ruleId:'HTTP_HTML_INPUT_FLOW',kind:'HTML_TEXT_INPUT_FLOW',operation:endpoint,location,trace:flow,limitations:limits};
          append(result.nodeUses,witness,state.mod);if(!result.nodeUses.includes(witness)){note(state.mod,'HTML_PROOF_OUTPUT_BUDGET_EXCEEDED');return;}
          append(result.findings,{ruleId:'HTTP_HTML_INPUT_FLOW',kind:'CWE-79',confidence:'HIGH',disposition:'REVIEW_REQUIRED',source,sink:location,flow,defenses:[],limitations:limits,
            message:'요청값이 인코딩되지 않은 HTML 텍스트 위치에 전달되는 정적 경로입니다. 등록 근거: '+endpoint,
            recommendation:'해당 출력이 일반 텍스트라면 문맥에 맞는 HTML 텍스트 인코딩 또는 text/plain 응답을 검토하세요. HTML이 필요하면 검증된 정제 처리를 사용하고 정상 응답 구조를 보존하세요. 무해한 마커의 DOM 해석과 재검사를 확인하세요.'},state.mod);
        }
      }
    }

  }
  function response(v,options,node,state){
    const headers=options?.ref?.properties.get('headers');
    const entries=[...(headers?.ref?.properties??[])].filter(([k])=>k.toLowerCase()==='content-type');
    const mode=entries.length===1?mime(entries[0][1]):headers?'UNKNOWN':'PLAIN';
    observe(v,node,state,mode,'Response');
    const status=options?.ref?.properties.get('status');
    return {v,node,state,mode,valid:entries.length===1&&typeof entries[0][1]?.constant==='string'&&/^text\/html(?:\s*;|$)/i.test(entries[0][1].constant)&&(!options||options.ref&&!options.ref.unknown&&[...options.ref.properties.keys()].every(k=>['headers','status'].includes(k)))&&(!status||!status.unknown&&Number.isInteger(status.constant)&&status.constant>=200&&status.constant<=599&&![204,205,304].includes(status.constant))};
  }
  let intrinsicMutation;
  function transform(base,args,method){
    // Submitted intrinsic/prototype mutation invalidates the narrow replacement proof.
    const mutated=intrinsicMutation??=([...modules.values()].some(m=>/\b(?:prototype|defineProperty|defineProperties)\b|\.replaceAll\s*=|\[\s*['"]replaceAll['"]\s*\]\s*=/.test(m.ast?.text??'')));
    return encodeReplace(base,args,method,mutated);
  }
  function status(receiver,args,state){
    const updated={...receiver,htmlStatus:args.length===1&&!args[0]?.unknown?args[0].constant:'UNKNOWN'};
    for(const[k,v]of state.vars)if(v===receiver)state.vars.set(k,updated);
    return updated;
  }
  function output(receiver,args,node,state,method){
    const prior=state.context.htmlOutputStarted;state.context.htmlOutputStarted=true;
    if(args.length&&['send','write','end','render'].includes(method))observe(args[0],node,state,receiver.htmlResponseType,method,
      !prior&&args.length===1&&!receiver.unknown&&!receiver.ref?.unknown&&(receiver.htmlResponseType===undefined||receiver.htmlTextMime===true)&&(receiver.htmlStatus===undefined||Number.isInteger(receiver.htmlStatus)&&receiver.htmlStatus>=200&&receiver.htmlStatus<=599&&![204,205,304].includes(receiver.htmlStatus))&&state.context.htmlMethod!=='HEAD');
  }
  function returned(v,context){
    if(v.tag!=='exposureResponse'||v.unknown||v.htmlResponseUncertain||v.htmlPending?.length!==1||context.htmlOpaqueCall||context.unresolved)return;
    const p=v.htmlPending[0];if(!p.valid)return;
    if(context.entry?.kind!=='NEXT_ROUTE_HANDLER'||!['GET','POST','PUT','PATCH','DELETE','OPTIONS'].includes(context.htmlMethod))return;
    // Review was retained at construction; only the returned native response gets a Finding.
    observe(p.v,p.node,{...p.state,context},p.mode,'Response',true);
  }
  return {header,observe,response,transform,status,output,returned};
}
