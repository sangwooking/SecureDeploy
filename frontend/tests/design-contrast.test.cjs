const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const css=fs.readFileSync(path.join(__dirname,'../src/product.css'),'utf8');
function token(n){const values=[...css.matchAll(new RegExp('--'+n+':\\s*(#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3})','g'))];assert.ok(values.length,n);const v=values.at(-1)[1];return v.length===4?"#"+[...v.slice(1)].map(c=>c+c).join(""):v;}
function light(s){const rgb=s.slice(1).match(/../g).map(h=>parseInt(h,16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);return rgb[0]*.2126+rgb[1]*.7152+rgb[2]*.0722;}
test('shared normal-text and primary-action colors meet WCAG AA contrast',()=>{for(const [fg,bg]of [['ink','surface'],['muted','surface'],['muted','canvas'],['surface','accent'],['warning-ink','warning-surface']]){const values=[light(token(fg)),light(token(bg))].sort((a,b)=>b-a);assert.ok((values[0]+.05)/(values[1]+.05)>=4.5,fg+'/'+bg);}});
