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
  // Todas as consultas abaixo exigem sessão autenticada. Nenhuma rota de escrita é exposta.
  if(request.method==="GET"&&(
   url.pathname==="/api/products"||
   url.pathname==="/api/product-statuses"||
   /^\/api\/items\/(products|skus|kits)\/[0-9]+$/.test(url.pathname)||
   /^\/api\/products\/[0-9]+$/.test(url.pathname)
  )){
   const authHeader=request.headers.get("Authorization")||"";
   const raw=authHeader.startsWith("Bearer ")?authHeader.slice(7):"";
   if(!await checkToken(raw,env.ADMIN_SESSION_SECRET,env.ADMIN_USERNAME))return output({error:"UNAUTHORIZED"},401,cors);
   if(!env.LAYER_API_USERNAME||!env.LAYER_API_PASSWORD)return output({error:"LAYER_NOT_CONFIGURED"},503,cors);
   const base="https://projetos.layer.core.dcg.com.br/api/v3";
   try{
    const tokenResponse=await fetch(base+"/auth/token",{
     method:"POST",headers:{"Content-Type":"application/json",Accept:"application/json"},
     body:JSON.stringify({username:env.LAYER_API_USERNAME,password:env.LAYER_API_PASSWORD}),
     signal:AbortSignal.timeout(10000)
    });
    if(!tokenResponse.ok)return output({error:"LAYER_AUTH_FAILED",upstreamStatus:tokenResponse.status},502,cors);
    const tokenData=await tokenResponse.json();
    if(!tokenData.accessToken)return output({error:"LAYER_TOKEN_MISSING"},502,cors);
    async function layerGet(path){
     const res=await fetch(base+path,{
      method:"GET",headers:{Accept:"application/json",Authorization:"Bearer "+tokenData.accessToken},
      signal:AbortSignal.timeout(14000)
     });
     if(!res.ok)return {error:true,status:res.status};
     return {error:false,data:await res.json()};
    }
    if(url.pathname==="/api/products"){
     const pageStr=url.searchParams.get("page")||"1",sizeStr=url.searchParams.get("pageSize")||"50";
     const type=url.searchParams.get("type")||"products";
     if(!/^[0-9]+$/.test(pageStr)||!/^[0-9]+$/.test(sizeStr)||!["products","skus","kits","all"].includes(type))
      return output({error:"INVALID_PARAMETERS"},400,cors);
     const page=Number(pageStr),pageSize=Number(sizeStr);
     if(!Number.isSafeInteger(page)||page<1||page>100000||!Number.isSafeInteger(pageSize)||pageSize<1||pageSize>100)
      return output({error:"INVALID_PAGINATION"},400,cors);
     // Kits são discriminados no resultado de produtos (catalogItemType=Bundle).
     // O OpenAPI não documenta GET /catalog/bundles; SKU tem listagem própria.
     const sources=type==="skus"?["skus"]:type==="all"?["products","skus"]:["products"];
     const parts=await Promise.all(sources.map(async kind=>{
      const response=await layerGet("/catalog/"+kind+"?page="+page+"&pageSize="+pageSize);
      if(response.error)return {error:true,upstreamStatus:response.status};
      const payload=response.data||{},items=Array.isArray(payload.items)?payload.items:[];
      return {kind,totalCount:payload.totalCount??items.length,totalPages:payload.totalPages??1,
       items:items.map(item=>({
        entityType:kind==="skus"?"skus":item.catalogItemType==="Bundle"?"kits":"products",
        catalogItemType:item.catalogItemType??null,
        id:item.id??null,sku:item.sku??null,integrationId:item.integrationId??null,
        name:item.name??null,brand:item.brandName??null,brandId:item.brandId??null,
        isVisible:item.isVisible??null,upc:item.upc??null,
        createdAt:item.createdAt??null,modifiedAt:item.modifiedAt??null
       }))}
     }));
     if(parts.some(part=>part.error))return output({error:"LAYER_PRODUCTS_FAILED",upstreamStatus:parts.find(p=>p.error).upstreamStatus},502,cors);
     let items=parts.flatMap(part=>part.items);
     if(type==="kits")items=items.filter(i=>i.entityType==="kits");
     if(type==="products")items=items.filter(i=>i.entityType==="products");
     return output({source:"layer-test",type,page,pageSize,items,
      totalCount:type==="kits"?null:type==="products"?null:parts.reduce((sum,part)=>sum+Number(part.totalCount||0),0),
      totalPages:type==="all"?Math.max(...parts.map(p=>p.totalPages)):parts[0]?.totalPages??1,
      partialTypeCount:["products","kits"].includes(type)},200,cors);
    }
    if(url.pathname==="/api/product-statuses"){
     const result=await layerGet("/catalog/product-statuses?page=1&pageSize=100");
     if(result.error)return output({error:"LAYER_STATUSES_FAILED",upstreamStatus:result.status},502,cors);
     return output({items:(result.data?.items||[]).map(i=>({id:i.id,status:i.status,color:i.color,isDefault:i.isDefault}))},200,cors);
    }
    const matches=url.pathname.match(/^\/api\/items\/(products|skus|kits)\/([0-9]+)$/);
    const kind=matches?matches[1]:"products";
    const id=matches?matches[2]:url.pathname.split("/").pop();
    const upstream=kind==="kits"?"/catalog/bundles/"+id:kind==="skus"?"/catalog/skus/"+id:"/catalog/products/"+id;
    const detail=await layerGet(upstream);
    if(detail.error)return output({error:detail.status===404?"ITEM_NOT_FOUND":"LAYER_DETAIL_FAILED",upstreamStatus:detail.status},detail.status===404?404:502,cors);
    const obj=detail.data?.data&&typeof detail.data.data==="object"?detail.data.data:detail.data;
    // Esquema de leitura: somente campos de cadastro conhecidos da API v3.
    const allow=kind==="skus"?
     ["id","sku","integrationId","name","productIds","productDefinitionId","variationProperties","suppliers","upc","display","dimensions","inventorySettings","misc"]:
     kind==="kits"?
     ["id","behavior","sku","integrationId","name","brandId","categories","isVisible","visibleFrom","visibleTo","isSearchable","rules","pricing","availability","shipping","itemCount","sendToMarketplace","seo","descriptions","display","composition","items"]:
     ["id","sku","integrationId","name","brandId","productDefinitionId","mainCategoryId","categories","flags","tags","display","seo","descriptions","shipping","references","availability","propertyValues","associations","associationDataSources","loyaltyPrograms","skuIds","ratingAverage","productStatusId"];
    const record={};for(const key of allow)if(obj&&Object.prototype.hasOwnProperty.call(obj,key))record[key]=obj[key];
    // Recursos complementares de leitura: se indisponíveis, o cadastro principal continua abrindo.
    const extraPaths=kind==="products"?
     {skus:"/catalog/products/"+id+"/skus",media:"/catalog/products/"+id+"/media"}:
     kind==="kits"?
     {composition:"/catalog/products/"+id+"/composition",media:"/catalog/products/"+id+"/media"}:{};
    const results=await Promise.all(Object.entries(extraPaths).map(async([key,path])=>{
     try{
      const response=await layerGet(path);
      if(response.error)return [key,null];
      return [key,Array.isArray(response.data)?response.data:Array.isArray(response.data?.items)?response.data.items:response.data];
     }catch{return [key,null]}
    }));
    for(const [key,value] of results)if(value!==null&&value!==undefined)record[key]=value;
    return output({source:"layer-test",entityType:kind,item:record,product:record},200,cors);
   }catch{return output({error:"LAYER_REQUEST_FAILED"},502,cors);}
  }
  return output({error:"NOT_FOUND"},404,cors);
 }
};
