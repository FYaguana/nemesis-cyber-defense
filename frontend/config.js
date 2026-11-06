// El frontend ahora habla SIEMPRE con rutas relativas (""), porque nginx
// hace de proxy inverso hacia el backend real (ver nginx.conf.template).
// Así el navegador ve un solo origen: no hace falta CORS ni cookies
// cross-site (SameSite=None). No editar a mano salvo que cambies de
// estrategia de despliegue.
window.NEMESIS_API_URL = "";
