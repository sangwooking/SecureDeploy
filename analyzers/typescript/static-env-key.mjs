// Closed string-only AST evaluation. No target functions, eval, module execution or environment reads.
export function staticEnvKey({ts,tick,note}) {
 return function evaluate(root,state) {
  let budget=96;const seen=new Set(),mod=state.mod;
  const charge=()=>{tick(mod);if(--budget<0)throw Error('KEY_BUDGET');};
  const unwrap=n=>{while(n&&(ts.isParenthesizedExpression(n)||ts.isAsExpression(n)||ts.isSatisfiesExpression(n)))n=n.expression;return n;};
  const parent=(a,b)=>{for(let p=b;p;p=p.parent)if(p===a)return true;return false;};
  const bounded=s=>{if(typeof s!=='string'||s.length>128)throw Error('KEY_SIZE');return s;};
  function read(node,depth=0,array=false) {
   charge();node=unwrap(node);if(!node||depth>8)throw Error('KEY_DEPTH');
   if(ts.isStringLiteralLike(node))return bounded(node.text);
   if(ts.isBinaryExpression(node)&&node.operatorToken.kind===ts.SyntaxKind.PlusToken)return bounded(read(node.left,depth+1)+read(node.right,depth+1));
   if(ts.isTemplateExpression(node)){let s=node.head.text;for(const p of node.templateSpans)s=bounded(s+read(p.expression,depth+1)+p.literal.text);return s;}
   if(array&&ts.isArrayLiteralExpression(node)&&node.elements.length<=16)return node.elements.map(n=>read(n,depth+1));
   if(ts.isIdentifier(node)){
    const name=node.text,index=mod.syntaxIndex,defs=index.declarations.get(name)??[];
    if(defs.length!==1||index.writes.has(name)||index.aliases.has(name))throw Error('KEY_BINDING');
    const d=defs[0];if(!ts.isVariableDeclaration(d)||!(d.parent.flags&ts.NodeFlags.Const)||!d.initializer||d.getStart()>=node.getStart()||!parent(d.parent.parent.parent,node)||seen.has(d))throw Error('KEY_LEXICAL');
    if(array){const scan=n=>{charge();if(ts.isIdentifier(n)&&n.text===name&&n!==d.name){const p=n.parent;if(!(ts.isPropertyAccessExpression(p)&&p.expression===n&&p.name.text==='join'&&ts.isCallExpression(p.parent)&&p.parent.expression===p))throw Error('KEY_ARRAY_ESCAPE');}ts.forEachChild(n,scan);};scan(mod.ast);}
    seen.add(d);try{return read(d.initializer,depth+1,array);}finally{seen.delete(d);}
   }
   if(ts.isCallExpression(node)&&ts.isPropertyAccessExpression(node.expression)&&node.expression.name.text==='join'&&node.arguments.length<=1){
    if(mod.syntaxIndex.bindings.has('Array')||mod.syntaxIndex.writes.has('Array'))throw Error('KEY_INTRINSIC');
    const elements=read(node.expression.expression,depth+1,true),separator=node.arguments.length?read(node.arguments[0],depth+1):',';
    if(!Array.isArray(elements))throw Error('KEY_JOIN');return bounded(elements.join(separator));
   }
   throw Error('KEY_UNSUPPORTED');
  }
  try{if(mod.syntaxIndex.nodes.some(n=>ts.isCallExpression(n)&&ts.isIdentifier(n.expression)&&['eval','Function'].includes(n.expression.text)))return;const value=read(root);if(typeof value==='string')return value;}catch{note(mod,'STATIC_ENVIRONMENT_KEY_UNRESOLVED');}
 };
}
