/**
 * New Admin LC — Cloudflare Worker / autenticação.
 * Deploy: copiar este arquivo para o Worker newadminlc-api.
 * Secrets obrigatórios (Settings > Variables and Secrets):
 * ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_SESSION_SECRET, ADMIN_ALLOWED_ORIGIN
 * ADMIN_ALLOWED_ORIGIN: origem exata do GitHub Pages (sem barra final).
 *
 * Não utilize credenciais da Layer como login do Admin.\n * Rotas: POST /auth/login, GET /auth/session, GET /api/products (autenticada, leitura apenas).\n * Secrets Layer: LAYER_API_USERNAME, LAYER_API_PASSWORD.
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
  if(/^\/api\/products\/[0-9]+$/.test(url.pathname)&&request.method==="GET"){
   const rawAuth=request.headers.get("Authorization")||"";
   const token=rawAuth.startsWith("Bearer ")?rawAuth.slice(7):"";
   const session=await checkToken(token,env.ADMIN_SESSION_SECRET,env.ADMIN_USERNAME);
   if(!session)return output({error:"UNAUTHORIZED"},401,cors);
   if(!env.LAYER_API_USERNAME||!env.LAYER_API_PASSWORD)return output({error:"LAYER_NOT_CONFIGURED"},503,cors);
   const id=url.pathname.split("/").pop();
   try{
    const authResponse=await fetch("https://projetos.layer.core.dcg.com.br/api/v3/auth/token",{
     method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json"},
     body:JSON.stringify({username:env.LAYER_API_USERNAME,password:env.LAYER_API_PASSWORD}),
     signal:AbortSignal.timeout(10000)
    });
    if(!authResponse.ok)return output({error:"LAYER_AUTH_FAILED",upstreamStatus:authResponse.status},502,cors);
    const credentials=await authResponse.json();
    if(!credentials.accessToken)return output({error:"LAYER_TOKEN_MISSING"},502,cors);
    const detailResponse=await fetch("https://projetos.layer.core.dcg.com.br/api/v3/catalog/products/"+id,{
     method:"GET",headers:{Accept:"application/json",Authorization:"Bearer "+credentials.accessToken},
     signal:AbortSignal.timeout(12000)
    });
    if(detailResponse.status===404)return output({error:"PRODUCT_NOT_FOUND"},404,cors);
    if(!detailResponse.ok)return output({error:"LAYER_PRODUCT_DETAIL_FAILED",upstreamStatus:detailResponse.status},502,cors);
    const payload=await detailResponse.json();
    const product=(payload&&typeof payload==="object"&&payload.data&&typeof payload.data==="object")?payload.data:payload;
    // Evita o encaminhamento indiscriminado de metadados/credenciais.
    const allowed=["id","sku","integrationId","name","status","active","description","shortDescription","brand","categories","category","skus","images","seo","slug","url","tags","attributes","productDefinition","type","createdAt","updatedAt"];
    const detail={};
    for(const field of allowed)if(product&&Object.prototype.hasOwnProperty.call(product,field))detail[field]=product[field];
    return output({source:"layer-test",product:detail},200,cors);
   }catch{return output({error:"LAYER_REQUEST_FAILED"},502,cors);}
  }
  if(url.pathname==="/api/products"&&request.method==="GET"){
   const authorization=request.headers.get("Authorization")||"";
   const raw=authorization.startsWith("Bearer ")?authorization.slice(7):"";
   const session=await checkToken(raw,env.ADMIN_SESSION_SECRET,env.ADMIN_USERNAME);
   if(!session)return output({error:"UNAUTHORIZED"},401,cors);
   if(!env.LAYER_API_USERNAME||!env.LAYER_API_PASSWORD)return output({error:"LAYER_NOT_CONFIGURED"},503,cors);
   const pageValue=url.searchParams.get("page")||"1";
   const sizeValue=url.searchParams.get("pageSize")||"20";
   if(!/^[0-9]+$/.test(pageValue)||!/^[0-9]+$/.test(sizeValue))return output({error:"INVALID_PAGINATION"},400,cors);
   const page=Number(pageValue),pageSize=Number(sizeValue);
   if(!Number.isSafeInteger(page)||page<1||page>100000||!Number.isSafeInteger(pageSize)||pageSize<1||pageSize>100)return output({error:"INVALID_PAGINATION"},400,cors);
   const layerBase="https://projetos.layer.core.dcg.com.br";
   try{
    const authRes=await fetch(layerBase+"/api/v3/auth/token",{
     method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},
     body:JSON.stringify({username:env.LAYER_API_USERNAME,password:env.LAYER_API_PASSWORD}),
     signal:AbortSignal.timeout(10000)
    });
    if(!authRes.ok)return output({error:"LAYER_AUTH_FAILED",upstreamStatus:authRes.status},502,cors);
    const auth=await authRes.json();
    if(!auth.accessToken)return output({error:"LAYER_TOKEN_MISSING"},502,cors);
    const productsRes=await fetch(layerBase+"/api/v3/catalog/products?page="+page+"&pageSize="+pageSize,{
     method:"GET",headers:{"Accept":"application/json","Authorization":"Bearer "+auth.accessToken},
     signal:AbortSignal.timeout(12000)
    });
    if(!productsRes.ok)return output({error:"LAYER_PRODUCTS_FAILED",upstreamStatus:productsRes.status},502,cors);
    const payload=await productsRes.json();
    const items=Array.isArray(payload.items)?payload.items:Array.isArray(payload.data)?payload.data:Array.isArray(payload)?payload:[];
    const mapped=items.map(item=>({
     id:item.id??null,sku:item.sku??null,integrationId:item.integrationId??null,
     name:item.name??null,status:item.status??null,
     active:item.active??null,
     brand:item.brand?.name??(typeof item.brand==="string"?item.brand:null)
    }));
    return output({source:"layer-test",page:payload.page??page,pageSize:payload.pageSize??pageSize,
     totalCount:payload.totalCount??payload.total??null,totalPages:payload.totalPages??null,items:mapped},200,cors);
   }catch{return output({error:"LAYER_REQUEST_FAILED"},502,cors);}
  }
  return output({error:"NOT_FOUND"},404,cors);
 }
};
