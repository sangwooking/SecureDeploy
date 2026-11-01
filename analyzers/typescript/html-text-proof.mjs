import {htmlParts} from './html-context.mjs';
// Deliberately small tokenizer. Ambiguous/malformed/foreign/raw-text syntax is not a proof.
// Unlike the review classifier, '>' inside a quoted attribute never returns to DATA.
export function rawHtmlTextInputs(value,{attributes=false}={}) {
 if(value?.unknown||value?.ref||value?.htmlPartsLimited)return [];
 let state='DATA',tag='',attr='',closing=false,quote='',stack=[],opaque=false,declaration='',rawTag='',rawBuffer='';
 const raw=new Set(['script','style','textarea','title','xmp','iframe','noembed','noframes','plaintext','noscript','svg','math','template']);
 const voids=new Set(['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']);
 const complete=()=>{const name=tag.toLowerCase();if(!name||['noscript','svg','math','template','plaintext'].includes(name))return false;if(!closing&&raw.has(name)){stack.push(name);rawTag=name;rawBuffer='';state='RAW';return true;}if(closing){if(stack.pop()!==name)return false;}else if(!voids.has(name))stack.push(name);state='DATA';return stack.length<=32;};
 const found=[];
 const parts=htmlParts(value);
 for(const [index,part] of parts.entries()) {
  if(part.text===undefined){
   const encoded=part.encoding?.join('|')==='&|<|>|"|\'';
   const sourceKnown=!opaque&&!part.unknown&&part.trace?.length&&!part.encoding?.length&&(!part.trace.some(l=>l.kind==='EXPRESS_PARAMS')||part.paramVerified);
   if(sourceKnown&&state==='DATA')found.push({...part,context:'HTML_TEXT'});
   // Only complete, quoted inert attributes. Event/URL/style/srcdoc/foreign syntax
   // remains review-only; HTML text encoding is never treated as a universal sanitizer.
   const suffix=parts[index+1]?.text;
   if(sourceKnown&&attributes&&state==='QUOTED'&&!raw.has(tag.toLowerCase())&&['title','alt','aria-label'].includes(attr.toLowerCase())
      &&typeof suffix==='string'&&suffix.startsWith(quote)&&/^[\s>]/.test(suffix.slice(1)))
     found.push({...part,context:'HTML_ATTRIBUTE',attribute:attr.toLowerCase()});
   if(!encoded||!['DATA','QUOTED'].includes(state))opaque=true;
   continue;
  }
  if(opaque)continue;
  for(const ch of part.text){
   if(state==='DATA'){if(ch==='<'){state='OPEN';tag='';closing=false;}}
   else if(state==='OPEN'){if(ch==='!'){state='DECLARATION';declaration='!';}else if(ch==='/'&&!closing){closing=true;state='NAME_START';}else if(/[A-Za-z]/.test(ch)){tag=ch;state='NAME';}else{opaque=true;break;}}
   else if(state==='DECLARATION'){declaration+=ch;if(declaration.length>512){opaque=true;break;}if(ch==='>'){const d=declaration.slice(0,-1);if(/^!doctype\s+html\s*$/i.test(d)||d.startsWith('!--')&&d.endsWith('--')&&!d.slice(3,-2).includes('--'))state='DATA';else{opaque=true;break;}}}
   else if(state==='RAW'){rawBuffer=(rawBuffer+ch).slice(-64);if(rawBuffer.toLowerCase().endsWith('</'+rawTag+'>')){stack.pop();state='DATA';rawBuffer='';}}
   else if(state==='NAME_START'){if(/[A-Za-z]/.test(ch)){tag=ch;state='NAME';}else{opaque=true;break;}}
   else if(state==='NAME'){if(/[A-Za-z0-9-]/.test(ch))tag+=ch;else if(ch==='>'){if(!complete()){opaque=true;break;}}else if(/\s/.test(ch)&&!closing)state='BEFORE_ATTR';else{opaque=true;break;}}
   else if(state==='BEFORE_ATTR'){if(/\s/.test(ch))continue;if(ch==='>'){if(!complete()){opaque=true;break;}}else if(/[A-Za-z_:]/.test(ch)){attr=ch;state='ATTR';}else{opaque=true;break;}}
   else if(state==='ATTR'){if(/[A-Za-z0-9_:.-]/.test(ch))attr+=ch;else if(ch==='=')state='VALUE';else if(/\s/.test(ch))state='AFTER_ATTR';else if(ch==='>'){if(!complete()){opaque=true;break;}}else{opaque=true;break;}}
   else if(state==='AFTER_ATTR'){if(/\s/.test(ch))continue;if(ch==='=')state='VALUE';else if(ch==='>'){if(!complete()){opaque=true;break;}}else{opaque=true;break;}}
   else if(state==='VALUE'){if(/\s/.test(ch))continue;if(ch==='"'||ch==="'"){quote=ch;state='QUOTED';}else{opaque=true;break;}}
   else if(state==='QUOTED'){if(ch===quote)state='BEFORE_ATTR';}
  }
 }
 return found.slice(0,4);
}
