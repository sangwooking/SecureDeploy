import {RegExpParser} from '@eslint-community/regexpp';

// Parse syntax only. Never compile or execute a supplied regular expression.
export function regexPlan(text,charge) {
  if(text.length>1024)return;
  try {
    const ast=new RegExpParser({ecmaVersion:2024}).parseLiteral(text);
    if(ast.flags.global||ast.flags.sticky||ast.flags.unicode||ast.flags.unicodeSets||ast.flags.hasIndices)return;
    const captures=[];let nodes=0;
    function inspect(n,depth=0,optional=false){
      charge();if(++nodes>256||depth>16)throw Error('REGEX_LIMIT');
      if(n.type==='Character')return {restricted:/^[A-Za-z0-9_./:-]$/.test(String.fromCodePoint(n.value)),broad:false,fixed:ast.flags.ignoreCase?undefined:String.fromCodePoint(n.value)};
      if(n.type==='CharacterSet')return {restricted:!n.negate&&['digit','word'].includes(n.kind),broad:n.kind==='any'};
      if(n.type==='CharacterClassRange')return {restricted:n.min.value<=n.max.value&&n.max.value-n.min.value<=127&&Array.from({length:n.max.value-n.min.value+1},(_,i)=>String.fromCodePoint(n.min.value+i)).every(c=>/^[A-Za-z0-9_./:-]$/.test(c)),broad:false};
      if(n.type==='Assertion'&&['start','end'].includes(n.kind))return {restricted:true,broad:false,fixed:''};
      if(n.type==='Quantifier'){const part=inspect(n.element,depth+1,optional||n.min===0);return {...part,fixed:undefined};}
      const children=n.alternatives??n.elements;
      if(!children||!['Pattern','Alternative','Group','CapturingGroup','CharacterClass'].includes(n.type)||n.negate)throw Error('REGEX_UNSUPPORTED');
      let slot;
      if(n.type==='CapturingGroup'){slot={optional};captures.push(slot);if(captures.length>16)throw Error('REGEX_LIMIT');}
      const parts=children.map(c=>inspect(c,depth+1,optional||!!n.alternatives&&children.length>1));
      const summary={restricted:parts.every(p=>p.restricted),broad:parts.some(p=>p.broad),
        fixed:n.type!=='CharacterClass'&&parts.every(p=>p.fixed!==undefined)&&(!n.alternatives||parts.length===1)?parts.map(p=>p.fixed).join(''):undefined};
      if(slot)Object.assign(slot,summary);
      return summary;
    }
    const whole=inspect(ast.pattern);
    return {key:text,captures:[whole,...captures]};
  } catch {return;}
}

export function regexFlow({ts,unwrap,expr,note,tick,loc,step,constant,unknown}) {
  function pattern(node,state){
    const plan=regexPlan(node.text,()=>tick(state.mod));
    if(!plan)note(state.mod,'REGEX_SYNTAX_OR_RESOURCE_UNSUPPORTED');
    return {tag:'regex-literal',trace:[],unknown:!plan,regexPlan:plan,ref:{properties:new Map(),trace:[],unknown:!plan,nodeIdentity:{}}};
  }
  function matchParts(node,state){
    node=unwrap(node);
    if(!ts.isCallExpression(node)||node.arguments.length!==1||!ts.isPropertyAccessExpression(node.expression))return;
    const method=node.expression.name.text;
    if(!['match','exec'].includes(method))return;
    const receiver=unwrap(node.expression.expression),arg=unwrap(node.arguments[0]);
    const simple=n=>ts.isIdentifier(n)||ts.isRegularExpressionLiteral(n)||ts.isStringLiteral(n);
    if(!simple(receiver)||!simple(arg))return;
    const re=method==='match'?arg:receiver;
    const input=method==='match'?receiver:arg;
    const source=ts.isIdentifier(input)?state.vars.get(input.text):undefined;
    if(source?.ref||source?.native||source?.tag==='function')return;
    const known=ts.isRegularExpressionLiteral(re)||ts.isIdentifier(re)&&state.vars.get(re.text)?.tag==='regex-literal';
    return known?{input:method==='match'?receiver:arg,re}:undefined;
  }
  function call(node,callee,receiver,args,state){
    if(!state.nodeMode||!ts.isPropertyAccessExpression(callee)||!['match','exec'].includes(callee.name.text))return;
    const isMatch=callee.name.text==='match',re=isMatch?args[0]:receiver,input=isMatch?receiver:args[0];
    if(re?.tag!=='regex-literal'&&isMatch===false)return;
    // Do not reinterpret object methods as String.prototype.match.
    if(isMatch&&(input?.ref||input?.native||input?.tag==='function'))return;
    const plan=re?.regexPlan;
    const valid=args.length===1&&plan&&!re.unknown&&!re.ref?.unknown&&!input?.unknown&&!input?.ref&&input?.inputShape!=='NON_STRING';
    if(!valid)note(state.mod,'REGEX_MATCH_CONTRACT_UNKNOWN');
    const proof=valid&&input.regexMatches?.includes(plan.key);
    return {tag:'regex-match',trace:[],unknown:!valid,regexMatch:{plan,input:input??unknown(),nonNull:!!proof}};
  }
  function property(base,key,node,state){
    if(base.tag!=='regex-match')return;
    const m=base.regexMatch,slot=m?.plan?.captures?.[Number(key)];
    const supported=/^(?:0|[1-9][0-9]?)$/.test(key)&&slot&&!slot.optional&&m.nonNull&&!base.unknown;
    if(!supported)note(state.mod,'REGEX_CAPTURE_UNVERIFIED');
    if(supported&&slot.fixed!==undefined)return constant(slot.fixed);
    const v=m?.input??unknown();
    return step({...v,tag:'regex-capture',regexMatches:undefined,regexMatch:undefined,
      unknown:!supported||v.unknown||!slot?.restricted&&!slot?.broad,
      shellRestricted:!!supported&&slot.restricted},loc(node,state.mod,'REGEX_CAPTURE',state.fn),state.mod);
  }
  function refine(original,accepted,state,depth=0){
    if(depth>6)return;const node=unwrap(original);
    if(ts.isPrefixUnaryExpression(node)&&node.operator===ts.SyntaxKind.ExclamationToken)return refine(node.operand,!accepted,state,depth+1);
    if(ts.isBinaryExpression(node)){
      const op=node.operatorToken.kind;
      if(op===ts.SyntaxKind.AmpersandAmpersandToken&&accepted||op===ts.SyntaxKind.BarBarToken&&!accepted){refine(node.left,accepted,state,depth+1);refine(node.right,accepted,state,depth+1);return;}
      const eq=[ts.SyntaxKind.EqualsEqualsToken,ts.SyntaxKind.EqualsEqualsEqualsToken].includes(op);
      const neq=[ts.SyntaxKind.ExclamationEqualsToken,ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(op);
      if(eq||neq){
        const a=unwrap(node.left),b=unwrap(node.right);
        const type=ts.isTypeOfExpression(a)&&ts.isStringLiteral(b)?[unwrap(a.expression),b.text]
          :ts.isTypeOfExpression(b)&&ts.isStringLiteral(a)?[unwrap(b.expression),a.text]:undefined;
        if(type&&ts.isIdentifier(type[0])){
          const v=state.vars.get(type[0].text),equal=accepted===eq;
          if(v&&(equal||type[1]==='string'))state.vars.set(type[0].text,{...v,inputShape:equal&&type[1]==='string'?'STRING':'NON_STRING'});
          return;
        }
        const target=a.kind===ts.SyntaxKind.NullKeyword?b:b.kind===ts.SyntaxKind.NullKeyword?a:undefined;
        if(target)return refine(target,accepted===neq,state,depth+1);
      }
    }
    if(!accepted)return;
    if(ts.isIdentifier(node)){
      const v=state.vars.get(node.text);
      if(v?.regexMatch&&!v.unknown)state.vars.set(node.text,{...v,regexMatch:{...v.regexMatch,nonNull:true}});
    }
    const parts=matchParts(node,state);
    if(parts&&ts.isIdentifier(parts.input)){
      const v=state.vars.get(parts.input.text),re=ts.isIdentifier(parts.re)?state.vars.get(parts.re.text):pattern(parts.re,state);
      if(v&&!v.unknown&&re?.regexPlan&&!re.unknown&&!re.ref?.unknown)state.vars.set(parts.input.text,{...v,regexMatches:[...new Set([...(v.regexMatches??[]),re.regexPlan.key])].slice(0,16)});
    }
  }
  return {pattern,call,property,refine,pureMatch:matchParts};
}
