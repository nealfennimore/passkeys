var R=Object.create;var D=Object.defineProperty;var $=Object.getOwnPropertyDescriptor;var j=Object.getOwnPropertyNames;var J=Object.getPrototypeOf,q=Object.prototype.hasOwnProperty;var I=(t,e)=>()=>(e||t((e={exports:{}}).exports,e),e.exports);var _=(t,e,r,a)=>{if(e&&typeof e=="object"||typeof e=="function")for(let n of j(e))!q.call(t,n)&&n!==r&&D(t,n,{get:()=>e[n],enumerable:!(a=$(e,n))||a.enumerable});return t};var F=(t,e,r)=>(r=t!=null?R(J(t)):{},_(e||!t||!t.__esModule?D(r,"default",{value:t,enumerable:!0}):r,t));var T=I(p=>{"use strict";Object.defineProperty(p,"__esModule",{value:!0});function d(t,e,r){var a;if(r===void 0&&(r={}),!e.codes){e.codes={};for(var n=0;n<e.chars.length;++n)e.codes[e.chars[n]]=n}if(!r.loose&&t.length*e.bits&7)throw new SyntaxError("Invalid padding");for(var i=t.length;t[i-1]==="=";)if(--i,!r.loose&&!((t.length-i)*e.bits&7))throw new SyntaxError("Invalid padding");for(var c=new((a=r.out)!=null?a:Uint8Array)(i*e.bits/8|0),s=0,o=0,l=0,u=0;u<i;++u){var B=e.codes[t[u]];if(B===void 0)throw new SyntaxError("Invalid character "+t[u]);o=o<<e.bits|B,s+=e.bits,s>=8&&(s-=8,c[l++]=255&o>>s)}if(s>=e.bits||255&o<<8-s)throw new SyntaxError("Unexpected end of data");return c}function y(t,e,r){r===void 0&&(r={});for(var a=r,n=a.pad,i=n===void 0?!0:n,c=(1<<e.bits)-1,s="",o=0,l=0,u=0;u<t.length;++u)for(l=l<<8|255&t[u],o+=8;o>e.bits;)o-=e.bits,s+=e.chars[c&l>>o];if(o&&(s+=e.chars[c&l<<e.bits-o]),i)for(;s.length*e.bits&7;)s+="=";return s}var O={chars:"0123456789ABCDEF",bits:4},U={chars:"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",bits:5},k={chars:"0123456789ABCDEFGHIJKLMNOPQRSTUV",bits:5},K={chars:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",bits:6},H={chars:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",bits:6},M={parse:function(e,r){return d(e.toUpperCase(),O,r)},stringify:function(e,r){return y(e,O,r)}},V={parse:function(e,r){return r===void 0&&(r={}),d(r.loose?e.toUpperCase().replace(/0/g,"O").replace(/1/g,"L").replace(/8/g,"B"):e,U,r)},stringify:function(e,r){return y(e,U,r)}},G={parse:function(e,r){return d(e,k,r)},stringify:function(e,r){return y(e,k,r)}},Q={parse:function(e,r){return d(e,K,r)},stringify:function(e,r){return y(e,K,r)}},X={parse:function(e,r){return d(e,H,r)},stringify:function(e,r){return y(e,H,r)}},Y={parse:d,stringify:y};p.base16=M;p.base32=V;p.base32hex=G;p.base64=Q;p.base64url=X;p.codec=Y});var te={[(-7).toString()]:"SHA-256",[(-35).toString()]:"SHA-384",[(-36).toString()]:"SHA-512"},re={[(-7).toString()]:"P-256",[(-35).toString()]:"P-384",[(-36).toString()]:"P-512"},ne={[(-7).toString()]:"ECDSA",[(-35).toString()]:"ECDSA",[(-36).toString()]:"ECDSA"};var f=F(T(),1),se=f.default.base16,ie=f.default.base32,ce=f.default.base32hex,le=f.default.base64,b=f.default.base64url,ue=f.default.codec;function A(t){return new TextDecoder().decode(b.parse(t,{loose:!0}))}function x(t){return b.stringify(new TextEncoder().encode(t),{pad:!1})}var L=new TextEncoder,N=new TextDecoder,v=L.encode.bind(L),Z=N.decode.bind(N);function z(t){let e=new Uint8Array(t),r="";for(var a=0;a<e.byteLength;a++)r+=String.fromCharCode(e[a]);return r}var m=x,E=A,C=t=>v(E(t)),g=t=>m(Z(t));var P=t=>m(z(t));window.fromBase64Url=E;window.toBase64Url=m;var S=(t,e={})=>fetch(new Request(`https://api.passkeys.workers.dev/${t}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(e),credentials:"include"})),h;(r=>{async function t(a){return await(await S("attestation/generate",{userId:a})).json()}r.generate=t;async function e(a){let n=a.response,i={kid:a.id,clientDataJSON:g(n.clientDataJSON),attestationObject:P(n.attestationObject),pubkey:P(n.getPublicKey()),coseAlg:n.getPublicKeyAlgorithm()};return window.pubkey=n.getPublicKey(),window.pubkey64=g(n.getPublicKey()),console.log(window.pubkey,window.pubkey64),await(await S("attestation/store",i)).json()}r.store=e})(h||={});var w;(r=>{async function t(){return await(await S("assertion/generate",{})).json()}r.generate=t;async function e(a){let n=a.response,i={kid:a.id,clientDataJSON:g(n.clientDataJSON),authenticatorData:g(n.authenticatorData),signature:g(n.signature)};return await(await S("assertion/verify",i)).json()}r.verify=e})(w||={});if(window.PublicKeyCredential){async function t(i,c){let s=crypto.randomUUID(),{challenge:o}=await h.generate(s),l={challenge:C(o),rp:{id:window.location.host,name:document.title},user:{id:v(s),name:c,displayName:""},pubKeyCredParams:[{type:"public-key",alg:-36},{type:"public-key",alg:-35},{type:"public-key",alg:-7}],authenticatorSelection:{userVerification:"preferred",residentKey:"required"},attestation:"indirect",timeout:6e4},u=await window.navigator.credentials.create({publicKey:l,signal:i.signal});return await h.store(u)}async function e(i){let{challenge:c}=await w.generate(),s={challenge:C(c),rpId:window.location.host,timeout:6e4},o=await window.navigator.credentials.get({publicKey:s,signal:i.signal,mediation:"optional"});return await w.verify(o)}let r=document.querySelector("button#cancel"),a=document.querySelector("textarea#output"),n=i=>async c=>{c.preventDefault();let s=new FormData(document.querySelector("form#passkeys")),o=new AbortController;r?.addEventListener("click",o.abort,{once:!0,signal:o.signal});let l=await i(o,s.get("username"));a&&(a.value=JSON.stringify(l,void 0,4)),o.abort()};document.querySelector("form#passkeys button#signup")?.addEventListener("click",n(t)),document.querySelector("form#passkeys button#login")?.addEventListener("click",n(e))}
//# sourceMappingURL=index.js.map
