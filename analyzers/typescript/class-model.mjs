// Parse-only class identities. No inheritance, initializers, accessors or async bootstrap.
export function classModels(api) {
  const {ts,limits,tick,note,unknown,constant,object,functionValue,invoke,loc,append,result}=api;
  const evidence=(kind,node,state,trace=[])=>append(result.nodeUses,{ruleId:'JS_SERVER_ENTRY_CONTEXT',kind,
    operation:'BOUNDED_CLASS_LINK',location:loc(node,state.mod,kind,state.fn),trace,
    limitations:['STATIC_LINK_NOT_RUNTIME_EXECUTION_PROOF']},state.mod);
  const rejected=(reason,node,state)=>{note(state.mod,reason);state.uncertain=true;
    evidence('UNSUPPORTED_OR_UNKNOWN',node,state);return unknown();};
  const unknownCall=(reason,node,state,values)=>{
    for(const v of values)if(v?.ref)api.invalidateNodeReference(v.ref,state,unknown());
    return rejected(reason,node,state);
  };
  const stat=n=>n.modifiers?.some(m=>m.kind===ts.SyntaxKind.StaticKeyword);
  function define(node,state) {
    if(node.heritageClauses?.length||ts.getDecorators(node)?.length)
      return rejected('CLASS_INHERITANCE_OR_DECORATOR_UNKNOWN',node,state);
    if(node.members.length>limits.maxFunctions)return rejected('CLASS_MEMBER_LIMIT',node,state);
    const model={ref:object('class').ref,methods:new Map(),ctor:undefined,node,mod:state.mod};
    const value={tag:'class',trace:[],unknown:false,ref:model.ref,classModel:model};
    for(const m of node.members){
      tick(state.mod);
      if(ts.isSemicolonClassElement(m))continue;
      if(ts.getDecorators(m)?.length||m.name&&(ts.isComputedPropertyName(m.name)||ts.isPrivateIdentifier(m.name)))
        return rejected('CLASS_DYNAMIC_MEMBER_UNKNOWN',m,state);
      if(stat(m)&&(ts.isMethodDeclaration(m)||ts.isGetAccessor(m)||ts.isSetAccessor(m))){
        note(state.mod,'CLASS_STATIC_MEMBER_NOT_INVOKED');continue;
      }
      if(ts.isConstructorDeclaration(m)&&m.body&&!model.ctor){
        if(m.parameters.some(p=>p.modifiers?.length||ts.getDecorators(p)?.length))
          return rejected('CLASS_PARAMETER_PROPERTY_OR_DECORATOR_UNKNOWN',m,state);
        model.ctor=functionValue(m,state,'constructor');continue;
      }
      if(!ts.isMethodDeclaration(m)||!m.body||!m.name||!ts.isIdentifier(m.name)||m.asteriskToken)
        return rejected('CLASS_FIELD_OR_ACCESSOR_UNKNOWN',m,state);
      const method=functionValue(m,state,m.name.text);
      if(!method.target)return rejected('CLASS_METHOD_BUDGET_UNKNOWN',m,state);
      method.target.classModel=model;model.methods.set(m.name.text,method);
    }
    // Class bodies capture their own named binding without hoisting a usable value.
    if(node.name)for(const f of [...model.methods.values(),model.ctor].filter(Boolean))f.target?.closure.set(node.name.text,value);
    evidence('CLASS_DEFINITION_LINKED',node,state);return value;
  }
  function construct(value,args,node,state){
    const model=value.classModel;
    if(value.unknown||model.ref.unknown)return rejected('CLASS_ORIGIN_MUTATED_UNKNOWN',node,state);
    const instance={...object('node-instance'),classModel:model};
    const ctor=model.ctor;
    evidence('CLASS_CONSTRUCTED',node,state,[loc(model.node,model.mod,'CLASS_DEFINITION',state.fn)]);
    if(ctor){
      if(!ctor.target)return rejected('CLASS_CONSTRUCTOR_BUDGET_UNKNOWN',node,state);
      evidence('CONSTRUCTOR_ARGUMENT_CONNECTED',node,state,[loc(ctor.target.node,model.mod,'CONSTRUCTOR_PARAMETERS',ctor.target)]);
      let simple=true;
      const scan=n=>{tick(state.mod);if(n!==ctor.target.node&&ts.isFunctionLike(n))return;
        if(ts.isReturnStatement(n)||ts.isThrowStatement(n)||ts.isTryStatement(n)||ts.isIfStatement(n)
            ||ts.isIterationStatement(n,false)||ts.isSwitchStatement(n))simple=false;
        if(ts.isBinaryExpression(n)&&ts.isPropertyAccessExpression(n.left)&&n.left.expression.kind===ts.SyntaxKind.ThisKeyword
            &&(ts.isArrowFunction(n.right)||ts.isFunctionExpression(n.right)))simple=false;
        ts.forEachChild(n,scan);};scan(ctor.target.node);
      if(!simple)return unknownCall('CLASS_CONSTRUCTOR_CONTROL_FLOW_UNKNOWN',node,state,args);
      const returned=invoke(ctor.target,args,state.depth+1,state.context,state.stack,state.uncertain,false,instance,true);
      if(returned.unknown){instance.unknown=true;instance.ref.unknown=true;note(state.mod,'CLASS_CONSTRUCTOR_EFFECT_UNKNOWN');}
      if(returned.ref&&!returned.unknown)return returned;
    }
    return instance;
  }
  function property(base,key,node,state){
    if(base.tag==='class'){
      if(key==='prototype')return {...object('class-prototype'),ref:base.ref};
      return rejected('CLASS_STATIC_ACCESS_UNKNOWN',node,state);
    }
    if(base.classModel){
      if(base.unknown||base.ref.unknown||base.classModel.ref.unknown)return unknown();
      if(base.ref.properties.has(key))return base.ref.properties.get(key);
      if(key==='constructor')return unknown();
      return base.classModel.methods.get(key)??constant(undefined);
    }
    if(base.target?.classModel&&key==='bind'&&!base.ref.properties.has('bind'))
      return {...object('class-bind'),boundMethod:base};
  }
  function call(node,receiver,args,state,callable){
    if(callable?.classModel&&callable.tag==='class')return {value:ts.isNewExpression(node)?construct(callable,args,node,state):rejected('CLASS_CALL_WITHOUT_NEW_UNKNOWN',node,state)};
    if(callable?.tag==='class-bind'){
      const method=callable.boundMethod;
      if(method.unknown||method.ref?.unknown||args.length!==1||args[0]?.classModel!==method.target.classModel||args[0].ref?.unknown||method.target.classModel.ref.unknown)
        return {value:rejected('CLASS_THIS_BINDING_UNKNOWN',node,state)};
      const bound={...object('class-bound'),classBoundMethod:method};bound.ref.properties.set('this',args[0]);
      return {value:bound};
    }
    if(callable?.tag==='class-bound'){
      const selected=callable.ref?.properties.get('this'),method=callable.classBoundMethod;
      if(callable.ref?.unknown||method.unknown||method.ref?.unknown||!selected||selected.ref?.unknown||method.target.classModel.ref.unknown||ts.isNewExpression(node))
        return {value:rejected('CLASS_THIS_BINDING_UNKNOWN',node,state)};
      if(method.target.node.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword))
        return {value:unknownCall('CLASS_ASYNC_EXECUTION_UNKNOWN',node,state,[selected,...args])};
      evidence('METHOD_CALL_CONNECTED',node,state,[loc(method.target.node,method.target.mod,'CLASS_METHOD_TARGET',method.target)]);
      return {value:invoke(method.target,args,state.depth+1,state.context,state.stack,state.uncertain,state.exposureUncertain,selected)};
    }
    if(!callable?.target?.classModel)return;
    const model=callable.target.classModel,selected=callable.target.lexicalThis??receiver;
    if(callable.unknown||callable.ref?.unknown||model.ref.unknown||!selected||selected.classModel!==model||selected.unknown||selected.ref?.unknown||ts.isNewExpression(node))
      return {value:rejected('CLASS_METHOD_RECEIVER_UNKNOWN',node,state)};
    if(callable.target.node.modifiers?.some(m=>m.kind===ts.SyntaxKind.AsyncKeyword))
      return {value:unknownCall('CLASS_ASYNC_EXECUTION_UNKNOWN',node,state,[selected,...args])};
    evidence('METHOD_CALL_CONNECTED',node,state,[loc(callable.target.node,model.mod,'CLASS_METHOD_TARGET',callable.target)]);
    // The existing bounded invoker performs the argument/return propagation.
  }
  return {define,property,call,evidence};
}
