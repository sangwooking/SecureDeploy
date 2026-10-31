function lastTag(text,name,close){let last=-1;const re=new RegExp('<'+(close?'/':'')+name+'(?=[\\s/>])','g');for(const match of text.matchAll(re))last=match.index;return last;}
// Abstract strings only. No browser, target code, template engine or sanitizer is executed.
export function htmlParts(v) {
 if(v?.htmlParts)return v.htmlParts;
 if(typeof v?.constant==='string'&&!v.unknown)return [{text:v.constant}];
 return [{input:true,trace:v?.trace??[],unknown:!!v?.unknown,encoding:v?.htmlEncoding??[]}];
}
export function joinHtml(left,right) {
 const parts=[...htmlParts(left),...htmlParts(right)];
 if(parts.length>32||parts.reduce((n,p)=>n+(p.text?.length??0),0)>4000)return {htmlPartsLimited:true};
 return {htmlParts:parts,htmlFlow:[...(left.htmlFlow??[]),...(right.htmlFlow??[])].slice(0,6)};
}
export function outputContexts(v) {
 const parts=htmlParts(v),out=[];let prefix='',opaque=false;
 for(const p of parts){
  if(p.text!==undefined){prefix+=p.text;continue;}
  if(!p.trace?.length){opaque=true;continue;}
  let context='HTML_TEXT';const lower=prefix.toLowerCase(),open=prefix.lastIndexOf('<'),close=prefix.lastIndexOf('>');
  if(opaque||v.htmlPartsLimited||p.unknown||prefix.includes('<!--')&&!prefix.includes('-->'))context='UNKNOWN';
  else if(lastTag(lower,'script',false)>lastTag(lower,'script',true))context='JAVASCRIPT';
  else if(lastTag(lower,'style',false)>lastTag(lower,'style',true))context='CSS';
  else if(open>close){
   const tag=prefix.slice(open),attr=tag.match(/\s([\w:-]+)\s*=\s*(["'])([^"']*)$/);
   if(!attr)context='UNKNOWN';
   else context=/^on/i.test(attr[1])?'JAVASCRIPT':attr[1].toLowerCase()==='style'?'CSS':attr[1].toLowerCase()==='srcdoc'?'HTML_DOCUMENT':/^(href|src|action|formaction|xlink:href)$/i.test(attr[1])?'URL_ATTRIBUTE':'HTML_ATTRIBUTE';
  }
  const encoded=p.encoding?.join('|')==='&|<|>|"|\''&&['HTML_TEXT','HTML_ATTRIBUTE'].includes(context);
  out.push({context,encoded,trace:p.trace});
  // An unencoded earlier interpolation may change the parser state of the next hole.
  if(!encoded)opaque=true;
 }
 return out;
}
export function encodeReplace(base,args,method,mutated) {
 if(method!=='replaceAll'||mutated||base?.ref||base?.unknown||args.length!==2||args.some(a=>a?.unknown||typeof a?.constant!=='string'))return null;
 const pairs=[['&','&amp;'],['<','&lt;'],['>','&gt;'],['"','&quot;'],["'",'&#x27;']];
 const steps=base.htmlEncoding??[],expected=pairs[steps.length];
 if(!expected||args[0].constant!==expected[0]||args[1].constant!==expected[1])return null;
 const {constant,htmlParts,...rest}=base;
 return {...rest,tag:'html-encoded-string',htmlString:true,htmlEncoding:[...steps,expected[0]]};
}
