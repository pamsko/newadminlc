/**
 * New Admin LC — Cloudflare Worker / autenticação.
 * Deploy: copiar este arquivo para o Worker newadminlc-api.
 * Secrets obrigatórios (Settings > Variables and Secrets):
 * ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_SESSION_SECRET, ADMIN_ALLOWED_ORIGIN
 * ADMIN_ALLOWED_ORIGIN: origem exata do GitHub Pages (sem barra final).
 *
 * Não utilize credenciais da Layer como login do Admin.
 */
const encoder = new TextEncoder();
const noStore = {"Cache-Control":"no-store","X-Content-Type-Options":"nosniff"};
const output = (body,status=200,headers={}) => new Response(JSON.stringify(body),{status,headers:{"Content-Type":"application/json; charset=utf-8",...noStore,...headers}});
function base64url(bytes){let text="";for(const byte of bytes)text+=String.fromCharCode(byte);return btoa(text).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");}
function decode64url(input){const raw=atob(input.replace(/-/g,"+").replace(/_/g,"/").padEnd(Math.ceil(input.length/4)*4,"="));return Uint8Array.from(raw,c=>c.charCodeAt(0));}
async function keyFrom(secret){return crypto.subtle.importKey("raw",encoder.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);}
async function createToken(user,secret){
 const payload={sub:user,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+8*3600};
 const header=base64url(encoder.encode(JSON.stringify({alg:"HS256",typ:"JWT"})));
 const content=base64url(encoder.encode(JSON.stringify(payload)));
 const signingInput=header+"."+content;
 const signature=await crypto.subtle.sign("HMAC",await keyFrom(secret),encoder.encode(signingInput));
 return signingInput+"."+base64url(new Uint8Array(signature));
}
async function checkToken(raw,secret,expectedUser){
 if(!raw||raw.length>4096)return null;
 try{
  const parts=raw.split(".");if(parts.length!==3)return null;
  const header=JSON.parse(new TextDecoder().decode(decode64url(parts[0])));
  if(header.alg!=="HS256"||header.typ!=="JWT")return null;
  const valid=await crypto.subtle.verify("HMAC",await keyFrom(secret),decode64url(parts[2]),encoder.encode(parts[0]+"."+parts[1]));
  if(!valid)return null;
  const data=JSON.parse(new TextDecoder().decode(decode64url(parts[1])));
  const now=Math.floor(Date.now()/1000);
  return data.sub===expectedUser&&Number.isFinite(data.exp)&&data.exp>now&&data.iat<=now?data:null;
 }catch{return null;}
}
async function safeEqual(a,b){
 const [x,y]=await Promise.all([crypto.subtle.digest("SHA-256",encoder.encode(a)),crypto.subtle.digest("SHA-256",encoder.encode(b))]);
 const A=new Uint8Array(x),B=new Uint8Array(y);let diff=0;
 for(let i=0;i<A.length;i++)diff|=A[i]^B[i];
 return diff===0;
}
export default {
 async fetch(request,env){
  const url=new URL(request.url);
  const origin=request.headers.get("Origin")||"";
  const allowed=(env.ADMIN_ALLOWED_ORIGIN||"").replace(/\/$/,"");
  const cors=origin&&origin===allowed?{"Access-Control-Allow-Origin":allowed,"Access-Control-Allow-Headers":"Content-Type, Authorization","Access-Control-Allow-Methods":"POST, GET, OPTIONS","Vary":"Origin"}:{};
  if(request.method==="OPTIONS")return origin===allowed?new Response(null,{status:204,headers:{...cors,...noStore}}):new Response(null,{status:403,headers:noStore});
  if(origin&&origin!==allowed)return output({error:"ORIGIN_NOT_ALLOWED"},403);
  if(!env.ADMIN_USERNAME||!env.ADMIN_PASSWORD||!env.ADMIN_SESSION_SECRET||env.ADMIN_SESSION_SECRET.length<32||!allowed){
   return output({error:"AUTH_NOT_CONFIGURED"},503,cors);
  }
  if(url.pathname==="/auth/login"&&request.method==="POST"){
   if(Number(request.headers.get("Content-Length")||0)>4096)return output({error:"INVALID_REQUEST"},413,cors);
   let body;try{body=await request.json();}catch{return output({error:"INVALID_REQUEST"},400,cors);}
   const username=typeof body?.username==="string"?body.username.trim():"";
   const password=typeof body?.password==="string"?body.password:"";
   if(username.length>200||password.length>200||!username||!password)return output({error:"INVALID_CREDENTIALS"},401,cors);
   const [userOk,passOk]=await Promise.all([safeEqual(username,env.ADMIN_USERNAME),safeEqual(password,env.ADMIN_PASSWORD)]);
   if(!userOk||!passOk)return output({error:"INVALID_CREDENTIALS"},401,cors);
   const token=await createToken(env.ADMIN_USERNAME,env.ADMIN_SESSION_SECRET);
   return output({token,username:env.ADMIN_USERNAME,expiresIn:8*3600},200,cors);
  }
  if(url.pathname==="/auth/session"&&request.method==="GET"){
   const value=request.headers.get("Authorization")||"";
   const raw=value.startsWith("Bearer ")?value.slice(7):"";
   const session=await checkToken(raw,env.ADMIN_SESSION_SECRET,env.ADMIN_USERNAME);
   if(!session)return output({authenticated:false},401,cors);
   return output({authenticated:true,username:session.sub,expiresAt:session.exp},200,cors);
  }
  return output({error:"NOT_FOUND"},404,cors);
 }
};
