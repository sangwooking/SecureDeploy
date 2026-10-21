import ts from 'typescript';

const strong = /^(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{24,}|AKIA[A-Z0-9]{16}|sb_secret_[A-Za-z0-9_-]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/;
const unwrap=n=>{while(n&&(ts.isParenthesizedExpression(n)||ts.isAsExpression(n)||ts.isNonNullExpression(n)))n=n.expression;return n;};
const name=n=>n&&(ts.isIdentifier(n)||ts.isStringLiteral(n))?n.text:undefined;
const member=(object,key)=>{
  const p=object&&ts.isObjectLiteralExpression(object)?object.properties.find(p=>(ts.isPropertyAssignment(p)||ts.isShorthandPropertyAssignment(p))&&name(p.name)===key):undefined;
  return p&&(ts.isShorthandPropertyAssignment(p)?p.name:p.initializer);
};

// Negative proof only. No code evaluation, module loading or arbitrary library calls.
export function displayContexts(files, rows, deadline) {
  const modules=[];let steps=0;
  const tick=()=>{if(++steps>200000||Date.now()>deadline)throw Error('CONTEXT_BUDGET');};
  try {
    for(const file of files){
      if(file.prefixOnly||typeof file.content!=='string'||file.content.length>250000)continue;
      const row=rows.find(r=>r.filePath===file.filePath&&r.status==='PARSED');if(!row)continue;
      const ast=ts.createSourceFile(file.filePath,file.content,ts.ScriptTarget.Latest,true,/\.[jt]sx$/.test(file.filePath)?ts.ScriptKind.TSX:ts.ScriptKind.TS);
      if(ast.parseDiagnostics.length)continue;
      const nodes=[],imports=new Map(),bindings=new Map(),writes=new Set();
      const visit=n=>{
        tick();nodes.push(n);
        if(ts.isImportDeclaration(n)&&ts.isStringLiteral(n.moduleSpecifier)){
          if(n.importClause?.name)imports.set(n.importClause.name.text,{spec:n.moduleSpecifier.text,key:'default'});
          for(const p of n.importClause?.namedBindings?.elements??[])imports.set(p.name.text,{spec:n.moduleSpecifier.text,key:p.propertyName?.text??p.name.text});
        }
        if(n.name&&ts.isIdentifier(n.name)&&(ts.isVariableDeclaration(n)||ts.isParameter(n)||ts.isFunctionDeclaration(n)||ts.isClassDeclaration(n)||ts.isBindingElement(n))){
          const list=bindings.get(n.name.text)??[];list.push(n);bindings.set(n.name.text,list);
        }
        if(ts.isBinaryExpression(n)&&ts.isAssignmentOperator(n.operatorToken.kind)||ts.isDeleteExpression(n)||ts.isPostfixUnaryExpression(n)){
          let base=ts.isBinaryExpression(n)?n.left:n.expression??n.operand;
          while(base&&(ts.isPropertyAccessExpression(base)||ts.isElementAccessExpression(base)))base=base.expression;
          if(base&&ts.isIdentifier(base))writes.add(base.text);
        }
        ts.forEachChild(n,visit);
      };visit(ast);
      modules.push({file,row,ast,nodes,imports,bindings,writes});
    }
    const providers=[];
    for(const m of modules){
      const {nodes,imports,bindings,writes}=m;
      for(const call of nodes.filter(n=>ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.name.text==='init')){
        tick();let root=call.expression.expression,valid=true;
        while(ts.isCallExpression(root)&&ts.isPropertyAccessExpression(root.expression)&&root.expression.name.text==='use'){
          const plugin=root.arguments[0];const binding=plugin&&ts.isIdentifier(plugin)?imports.get(plugin.text):undefined;
          valid&&=root.arguments.length===1&&binding?.spec==='react-i18next'&&binding.key==='initReactI18next';root=root.expression.expression;
        }
        if(!valid||!ts.isIdentifier(root)||imports.get(root.text)?.spec!=='i18next'||imports.get(root.text)?.key!=='default'||writes.has(root.text)||bindings.has(root.text))continue;
        if(nodes.some(n=>ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)&&n.expression.expression.getText(m.ast)===root.text&&!['init','use','changeLanguage','t'].includes(n.expression.name.text)))continue;
        const options=unwrap(call.arguments[0]);if(!options||member(options,'backend'))continue;
        let resources=unwrap(member(options,'resources'));
        if(resources&&ts.isIdentifier(resources)){
          const ds=bindings.get(resources.text);if(ds?.length!==1||writes.has(resources.text)||!ts.isVariableDeclaration(ds[0])||!(ds[0].parent.flags&ts.NodeFlags.Const))continue;
          if(nodes.some(n=>ts.isIdentifier(n)&&n.text===resources.text&&n!==ds[0].name&&n!==resources
              && !(ts.isPropertyAssignment(n.parent)&&n.parent.name===n)
              && !(ts.isPropertyAccessExpression(n.parent)&&n.parent.name===n)))continue;
          resources=unwrap(ds[0].initializer);
        }
        const leaves=[];
        function dictionary(n,path=[]){
          tick();n=unwrap(n);if(!n||path.length>20)throw Error('DYNAMIC_RESOURCE');
          if(ts.isStringLiteralLike(n)){leaves.push({node:n,path,value:n.text});return;}
          if(ts.isNumericLiteral(n)||[ts.SyntaxKind.TrueKeyword,ts.SyntaxKind.FalseKeyword,ts.SyntaxKind.NullKeyword].includes(n.kind))return;
          if(ts.isArrayLiteralExpression(n)){n.elements.forEach((e,i)=>dictionary(e,[...path,String(i)]));return;}
          if(!ts.isObjectLiteralExpression(n))throw Error('DYNAMIC_RESOURCE');
          const seen=new Set();
          for(const p of n.properties){const key=name(p.name);if(!ts.isPropertyAssignment(p)||key===undefined||seen.has(key))throw Error('DYNAMIC_RESOURCE');seen.add(key);dictionary(p.initializer,[...path,key]);}
        }
        try{dictionary(resources);}catch{continue;}
        providers.push({m,leaves});
        for(const leaf of leaves){
          // Require the translation namespace, a descriptive multiword label,
          // and no opaque credential shape. Generic configuration objects do not qualify.
          const key=leaf.path.at(-1);
          if(leaf.path[1]!=='translation'||!/^(?:api[_-]?key|secret|token|accessToken|refreshToken)$/i.test(key??'')
              ||strong.test(leaf.value)||!/^\p{L}[\p{L}\p{N}\s.,!?'():;-]+$/u.test(leaf.value)||leaf.value.trim().split(/\s+/).length<2)continue;
          const line=m.ast.getLineAndCharacterOfPosition(leaf.node.getStart(m.ast)).line+1;
          const text=m.file.content.split('\n')[line-1];
          // Multiple declarations on one line need proof for every match.
          if([...text.matchAll(/(?:api[_-]?key|secret|token|accessToken|refreshToken)["']?\s*[:=]\s*["']/gi)].length===1)m.row.excludedSecretLines.push(line);
        }
      }
    }
    const providerMutation=modules.some(m=>[...m.imports].some(([id,imp])=>imp.spec==='i18next'&&imp.key==='default'
      && (m.writes.has(id)||m.nodes.some(n=>ts.isCallExpression(n)&&ts.isPropertyAccessExpression(n.expression)
        && n.expression.expression.getText(m.ast)===id&&!['init','use','changeLanguage','t'].includes(n.expression.name.text)))));
    for(const m of modules){
      const {nodes,bindings,writes,imports,ast,row}=m;
      const unique=id=>bindings.get(id)?.length===1&&!writes.has(id)?bindings.get(id)[0]:undefined;
      const declarationFor=node=>{
        if(!node||!ts.isIdentifier(node)||writes.has(node.text))return;
        const candidates=(bindings.get(node.text)??[]).map(decl=>{
          let scope=decl.parent;
          if(!ts.isParameter(decl))while(scope&&!ts.isBlock(scope)&&!ts.isSourceFile(scope)&&!ts.isFunctionLike(scope))scope=scope.parent;
          return {decl,scope};
        }).filter(x=>x.scope&&x.scope.pos<=node.pos&&x.scope.end>=node.end).sort((a,b)=>(a.scope.end-a.scope.pos)-(b.scope.end-b.scope.pos));
        return candidates.length&&!(candidates[1]&&candidates[0].scope===candidates[1].scope)?candidates[0].decl:undefined;
      };
      const origin=(original,stack=new Set(),depth=0)=>{
        tick();const n=unwrap(original);if(!n||depth>12||stack.has(n))return false;stack=new Set([...stack,n]);
        if(ts.isStringLiteralLike(n)||ts.isNumericLiteral(n))return true;
        if(ts.isTemplateExpression(n))return n.templateSpans.every(s=>origin(s.expression,stack,depth+1));
        if(ts.isBinaryExpression(n)&&[ts.SyntaxKind.PlusToken,ts.SyntaxKind.BarBarToken,ts.SyntaxKind.QuestionQuestionToken].includes(n.operatorToken.kind))return origin(n.left,stack,depth+1)&&origin(n.right,stack,depth+1);
        if(ts.isConditionalExpression(n))return origin(n.whenTrue,stack,depth+1)&&origin(n.whenFalse,stack,depth+1);
        if(ts.isCallExpression(n)&&n.arguments.length===1&&ts.isStringLiteral(n.arguments[0])&&n.expression.getText(ast)==='Deno.env.get'&&!bindings.has('Deno')&&!imports.has('Deno')&&!writes.has('Deno'))return true;
        if(ts.isIdentifier(n)){
          const decl=declarationFor(n);if(!decl)return false;
          if(ts.isVariableDeclaration(decl)&&(decl.parent.flags&ts.NodeFlags.Const))return origin(decl.initializer,stack,depth+1);
          if(ts.isParameter(decl)&&ts.isFunctionDeclaration(decl.parent)&&decl.parent.name&&!decl.parent.modifiers?.some(p=>p.kind===ts.SyntaxKind.ExportKeyword)){
            const fn=decl.parent,refs=nodes.filter(x=>ts.isIdentifier(x)&&x.text===fn.name.text&&x!==fn.name);
            if(!refs.length||refs.length>50||refs.some(x=>!ts.isCallExpression(x.parent)||x.parent.expression!==x))return false;
            return refs.every(x=>origin(x.parent.arguments[fn.parameters.indexOf(decl)],stack,depth+1));
          }
        }
        return false;
      };
      row.excludedRedirectLines=[];row.excludedHtmlLines=[];
      for(const n of nodes){
        tick();
        if(ts.isTemplateExpression(n)||ts.isStringLiteralLike(n)){
          if(!/(?:window\.)?location\.(?:href|assign)/.test(n.getText(ast))||!origin(n))continue;
          const start=ast.getLineAndCharacterOfPosition(n.getStart(ast)).line+1,end=ast.getLineAndCharacterOfPosition(n.end).line+1;
          for(let line=start;line<=end;line++)if(/(?:window\.)?location\.(?:href|assign)/.test(m.file.content.split('\n')[line-1]))row.excludedRedirectLines.push(line);
        }
        if(ts.isBinaryExpression(n)&&n.operatorToken.kind===ts.SyntaxKind.EqualsToken&&/^(?:window\.)?location\.href$/.test(n.left.getText(ast))&&origin(n.right))row.excludedRedirectLines.push(ast.getLineAndCharacterOfPosition(n.getStart(ast)).line+1);
        if(!ts.isJsxAttribute(n)||n.name.getText(ast)!=='dangerouslySetInnerHTML'||!n.initializer||!ts.isJsxExpression(n.initializer))continue;
        const content=unwrap(member(unwrap(n.initializer.expression),'__html'));let safe=content&&ts.isStringLiteralLike(content);
        if(!safe&&!providerMutation&&content&&ts.isCallExpression(content)&&ts.isIdentifier(content.expression)&&content.arguments.length===1&&ts.isStringLiteral(content.arguments[0])&&providers.length===1){
          const bound=unique(content.expression.text);
          const declaration=bound&&ts.isBindingElement(bound)?bound.parent.parent:undefined;
          const init=declaration&&ts.isVariableDeclaration(declaration)?unwrap(declaration.initializer):undefined;
          const imp=init&&ts.isCallExpression(init)&&ts.isIdentifier(init.expression)?imports.get(init.expression.text):undefined;
          if(imp?.spec==='react-i18next'&&imp.key==='useTranslation'&&!bindings.has(init.expression.text)&&!writes.has(init.expression.text)&&init.arguments.length===0&&(name(bound.propertyName)??name(bound.name))==='t'){
            const wanted=content.arguments[0].text,locales=new Set(providers[0].leaves.map(l=>l.path[0]));
            const values=providers[0].leaves.filter(l=>l.path[1]==='translation'&&l.path.slice(2).join('.')===wanted);
            safe=values.length===locales.size&&values.every(v=>!v.value.includes('{{'));
          }
        }
        if(safe)row.excludedHtmlLines.push(ast.getLineAndCharacterOfPosition(n.getStart(ast)).line+1);
      }
      row.excludedHtmlLines=row.excludedHtmlLines.filter(line=>[...m.file.content.split('\n')[line-1].matchAll(/dangerouslySetInnerHTML/g)].length===1);
      row.excludedRedirectLines=row.excludedRedirectLines.filter(line=>[...m.file.content.split('\n')[line-1].matchAll(/(?:window\.)?location\.(?:href|assign)/g)].length===1);
      for(const key of ['excludedSecretLines','excludedRedirectLines','excludedHtmlLines'])row[key]=[...new Set(row[key])].sort((a,b)=>a-b);
    }
  }catch{
    // Any budget exhaustion discards all new negative evidence, not just the last file.
    for(const row of rows){row.excludedRedirectLines=[];row.excludedHtmlLines=[];row.excludedSecretLines=[];}
  }
}
