const CACHE_NAME = "barreau-alger-shell-v2";
const APP_SHELL = ["./","./index.html","./requests.html","./organization.html","./manifest.json","./icons/app-icon.svg"];
self.addEventListener("install", event => event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)).then(() => self.skipWaiting())));
self.addEventListener("activate", event => event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key.startsWith("barreau-alger-shell-") && key !== CACHE_NAME).map(key => caches.delete(key)))).then(() => self.clients.claim())));
self.addEventListener("fetch", event => {
 const request=event.request;if(request.method!=="GET")return;
 const url=new URL(request.url);if(url.origin!==self.location.origin)return;
 if(request.mode==="navigate"){
  event.respondWith(fetch(request).then(response=>{if(response.ok)caches.open(CACHE_NAME).then(cache=>cache.put(request,response.clone()));return response;}).catch(async()=> (await caches.match(request))||(await caches.match("./index.html"))));return;
 }
 event.respondWith(caches.match(request).then(cached=>cached||fetch(request).then(response=>{if(response.ok&&(url.pathname.endsWith(".html")||url.pathname.endsWith(".json")||url.pathname.endsWith(".svg")))caches.open(CACHE_NAME).then(cache=>cache.put(request,response.clone()));return response;})));
});