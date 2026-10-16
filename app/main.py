import os
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

KC_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8081")
KC_JWKS_HOST = os.getenv("KEYCLOAK_JWKS_URL", KC_URL)  # host interno para buscar las llaves
REALM = os.getenv("KEYCLOAK_REALM", "cybersecurity")
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "fastapi-api")
ISSUER = f"{KC_URL}/realms/{REALM}"
JWKS_URL = f"{KC_JWKS_HOST}/realms/{REALM}/protocol/openid-connect/certs"

# La documentacion interactiva (/docs, /redoc, /openapi.json) queda apagada por
# defecto; solo se enciende en desarrollo con ENABLE_DOCS=true.
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "false").lower() == "true"

app = FastAPI(
    title="Dashboard API",
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8090"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "X-Permitted-Cross-Domain-Policies": "none",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-site",
}
# CSP estricta para una API que solo devuelve JSON. Con ENABLE_DOCS=true se omite
# para que Swagger UI y ReDoc (que cargan scripts desde un CDN) sigan funcionando.
if not ENABLE_DOCS:
    SECURITY_HEADERS["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


bearer = HTTPBearer()


async def current_user(
    creds: Annotated[HTTPAuthorizationCredentials, Depends(bearer)],
):
    token = creds.credentials
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(JWKS_URL, timeout=5)
            r.raise_for_status()
            jwks = r.json()
        header = jwt.get_unverified_header(token)
        key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
        if not key:
            raise HTTPException(401, "Signing key not found")
        return jwt.decode(token, key, algorithms=["RS256"], audience=CLIENT_ID, issuer=ISSUER)
    except (JWTError, httpx.HTTPError) as e:
        raise HTTPException(401, f"Token inválido: {e}")


class ItemIn(BaseModel):
    nombre: str
    categoria: str = ""


items = [
    {"id": 1, "nombre": "The Legend of Zelda", "categoria": "Videojuegos"},
]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/elementos")
def listar(user: Annotated[dict, Depends(current_user)]):
    return items


@app.post("/elementos", status_code=201)
def agregar(item: ItemIn, user: Annotated[dict, Depends(current_user)]):
    nuevo = {"id": len(items) + 1, **item.model_dump()}
    items.append(nuevo)
    return nuevo