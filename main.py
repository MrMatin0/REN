import asyncio
import json
import os
import hashlib
import secrets
import time
import re
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("REN-Gateway")

app = FastAPI(title="REN", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", "ren-default-secret-key"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connections: dict = {}
connection_sockets: dict = {}
link_ip_map: dict = defaultdict(set)
stats = {"total_bytes": 0, "total_requests": 0, "total_errors": 0, "start_time": time.time()}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

link_pending_usage: dict = defaultdict(int)
link_over_quota: dict = {}

CUSTOM_ADDRESSES: list = ["www.speedtest.net"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "ren_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

async def keep_alive():
    while True:
        await asyncio.sleep(600)
        try:
            domain = get_domain()
            if domain and domain != "localhost":
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.get(f"https://{domain}/health")
                logger.info("Keep-alive ping sent")
        except Exception:
            pass

def evaluate_quota(link) -> bool:
    if not link.get("active", True):
        return True
    if is_expired(link):
        return True
    if link["limit_bytes"] > 0 and link["used_bytes"] >= link["limit_bytes"]:
        return True
    return False

async def background_tasks():
    while True:
        await asyncio.sleep(15)
        try:
            total_flushed_bytes = 0
            async with LINKS_LOCK:
                for uid, pending in list(link_pending_usage.items()):
                    if pending > 0:
                        link_pending_usage[uid] = 0
                        link = LINKS.get(uid)
                        if link:
                            link["used_bytes"] += pending
                        total_flushed_bytes += pending
                
                if total_flushed_bytes > 0:
                    stats["total_bytes"] += total_flushed_bytes
                    current_hour = datetime.now().strftime("%H:00")
                    hourly_traffic[current_hour] += total_flushed_bytes

                for uid, link in LINKS.items():
                    link_over_quota[uid] = evaluate_quota(link)

            keys = list(hourly_traffic.keys())
            if len(keys) > 24:
                for k in keys[:-24]:
                    hourly_traffic.pop(k, None)

            async with SESSIONS_LOCK:
                now = time.time()
                expired_tokens = [tok for tok, exp in SESSIONS.items() if exp < now]
                for tok in expired_tokens:
                    SESSIONS.pop(tok, None)

        except Exception as e:
            logger.error(f"Background task error: {e}")

@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"REN started on port {CONFIG['port']}")
    asyncio.create_task(keep_alive())
    asyncio.create_task(background_tasks())

@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

def generate_vless_link(uuid: str, remark: str = "REN", address: str = None) -> str:
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    addr = address if address else domain
    path = f"/ws/{uuid}"
    params = {
        "encryption": "none",
        "security": "tls",
        "type": "ws",
        "host": domain,
        "path": path,
        "sni": domain,
        "fp": "chrome",
        "alpn": "http/1.1",
    }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{addr}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 * 1024 * 1024)
    if unit == "MB": return int(value * 1024 * 1024)
    if unit == "KB": return int(value * 1024)
    return int(value)

def compute_expiry(expiry_days) -> str:
    try:
        days = float(expiry_days or 0)
    except (TypeError, ValueError):
        days = 0
    if days <= 0:
        return ""
    return (datetime.now() + timedelta(days=days)).isoformat()

def is_expired(link) -> bool:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return False
    try:
        return datetime.now() >= datetime.fromisoformat(exp)
    except (TypeError, ValueError):
        return False

def expiry_epoch(link) -> int:
    exp = link.get("expiry") if isinstance(link, dict) else None
    if not exp:
        return 0
    try:
        return int(datetime.fromisoformat(exp).timestamp())
    except (TypeError, ValueError):
        return 0

async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["Default"] = {"label": "Default", "limit_bytes": 0, "used_bytes": 0, "max_connections": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""}

def get_client_ip(websocket: WebSocket) -> str:
    forwarded = websocket.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if websocket.client:
        return websocket.client.host
    return "unknown"

def count_connections_for_link(uid: str) -> int:
    return len(link_ip_map.get(uid, set()))

def remove_ip_from_link(uid: str, ip: str):
    if uid in link_ip_map:
        link_ip_map[uid].discard(ip)
        if not link_ip_map[uid]:
            link_ip_map.pop(uid, None)

async def close_connections_for_link(uid: str):
    to_close = [cid for cid, info in connections.items() if info.get("uuid") == uid]
    for cid in to_close:
        ws = connection_sockets.get(cid)
        if ws:
            try:
                await ws.close(code=1000, reason="link deleted")
            except Exception:
                pass
        connections.pop(cid, None)
        connection_sockets.pop(cid, None)
    link_ip_map.pop(uid, None)

@app.get("/")
async def root():
    return {"service": "REN", "version": "1.0", "status": "active", "domain": get_domain()}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    await destroy_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    return {"authenticated": await is_valid_session(token)}

@app.post("/api/change-password")
async def api_change_password(request: Request, _=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password") or "")
    new = str(body.get("new_password") or "")
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    AUTH["password_hash"] = hash_password(new)
    current_token = request.cookies.get(SESSION_COOKIE)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        if current_token:
            SESSIONS[current_token] = time.time() + SESSION_TTL
    return {"ok": True}

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    total_mb = round((stats["total_bytes"] + sum(link_pending_usage.values())) / (1024 * 1024), 2)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": total_mb,
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
        "domain": get_domain(),
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory_percent": psutil.virtual_memory().percent,
        "hourly_traffic": dict(hourly_traffic),
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "New Link").strip()[:60]
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', label):
        raise HTTPException(status_code=400, detail="Inbound name must contain only English letters, numbers, and characters: - _ . space")
    if not label:
        raise HTTPException(status_code=400, detail="Inbound name is required")
    async with LINKS_LOCK:
        if label in LINKS:
            raise HTTPException(status_code=400, detail="An inbound with this name already exists")
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    max_conn = int(body.get("max_connections") or 0)
    if max_conn < 0:
        max_conn = 0
    expiry = compute_expiry(body.get("expiry_days"))
    uid = label
    async with LINKS_LOCK:
        LINKS[uid] = {"label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "created_at": datetime.now().isoformat(), "active": True, "expiry": expiry}
    return {"uuid": uid, "label": label, "limit_bytes": limit_bytes, "used_bytes": 0, "max_connections": max_conn, "active": True, "expiry": expiry, "created_at": LINKS[uid]["created_at"], "vless_link": generate_vless_link(uid, remark=f"REN-{label}")}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            pending = link_pending_usage.get(uid, 0)
            used = data["used_bytes"] + pending
            result.append({"uuid": uid, "label": data["label"], "limit_bytes": data["limit_bytes"], "used_bytes": used, "max_connections": data.get("max_connections", 0), "active": data["active"], "expiry": data.get("expiry", ""), "expired": is_expired(data), "created_at": data["created_at"], "current_connections": count_connections_for_link(uid), "vless_link": generate_vless_link(uid, remark=f"REN-{data['label']}")})
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
            link_pending_usage[uid] = 0
        if "expiry_days" in body:
            LINKS[uid]["expiry"] = compute_expiry(body.get("expiry_days"))
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
        if "max_connections" in body:
            mc = int(body["max_connections"] or 0)
            LINKS[uid]["max_connections"] = mc if mc >= 0 else 0
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    await close_connections_for_link(uid)
    return {"ok": True}

@app.get("/api/domain")
async def get_custom_domain(_=Depends(require_auth)):
    async with CUSTOM_DOMAIN_LOCK:
        return {"domain": CUSTOM_DOMAIN}

@app.post("/api/domain")
async def set_custom_domain(request: Request, _=Depends(require_auth)):
    body = await request.json()
    domain = (body.get("domain") or "").strip().lower()
    if domain:
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if not re.match(r'^[a-z0-9\-_.]+$', domain):
            raise HTTPException(status_code=400, detail="Invalid domain format")
    async with CUSTOM_DOMAIN_LOCK:
        global CUSTOM_DOMAIN
        CUSTOM_DOMAIN = domain
    return {"ok": True, "domain": CUSTOM_DOMAIN}

@app.get("/api/addresses")
async def list_addresses(_=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        return {"addresses": list(CUSTOM_ADDRESSES)}

@app.post("/api/addresses")
async def add_address(request: Request, _=Depends(require_auth)):
    body = await request.json()
    address = (body.get("address") or "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")
    if not re.match(r'^[a-zA-Z0-9\-_. ]+$', address):
        raise HTTPException(status_code=400, detail="Address must contain only English letters, numbers, and characters: - _ .")
    async with CUSTOM_ADDRESSES_LOCK:
        if address in CUSTOM_ADDRESSES:
            raise HTTPException(status_code=400, detail="Address already exists")
        CUSTOM_ADDRESSES.append(address)
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.delete("/api/addresses/{index}")
async def delete_address(index: int, _=Depends(require_auth)):
    async with CUSTOM_ADDRESSES_LOCK:
        if 0 <= index < len(CUSTOM_ADDRESSES):
            CUSTOM_ADDRESSES.pop(index)
        else:
            raise HTTPException(status_code=404, detail="Address not found")
    return {"ok": True, "addresses": list(CUSTOM_ADDRESSES)}

@app.get("/api/links/{uid}/sub")
async def get_subscription(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
            
    vless_link = generate_vless_link(uid, remark=f"REN-{link['label']}")
    pending = link_pending_usage.get(uid, 0)
    used = link["used_bytes"] + pending
    limit = link["limit_bytes"]
    used_mb = round(used / (1024 * 1024), 2)
    limit_mb = round(limit / (1024 * 1024), 2) if limit > 0 else 0
    pct = round((used / limit) * 100, 1) if limit > 0 else 0
    remaining_mb = round((limit - used) / (1024 * 1024), 2) if limit > 0 else 0
    import base64
    sub_content = f"""# REN Subscription
# Label: {link['label']}
# Used: {used_mb} MB / {limit_mb if limit > 0 else 'Unlimited'} MB
# Remaining: {remaining_mb if limit > 0 else 'Unlimited'} MB
# Usage: {pct}%
# Status: {'Active' if link['active'] else 'Disabled'}
# Expiry: {link.get('expiry', '')[:10] if link.get('expiry') else 'Unlimited'}
{vless_link}"""
    encoded = base64.b64encode(sub_content.encode()).decode()
    return {
        "subscription_url": f"{get_domain()}/api/links/{uid}/sub",
        "config": vless_link,
        "label": link["label"],
        "used_bytes": used,
        "limit_bytes": limit,
        "used_mb": used_mb,
        "limit_mb": limit_mb,
        "remaining_mb": remaining_mb,
        "usage_percent": pct,
        "active": link["active"],
        "sub_base64": encoded,
        "sub_text": sub_content,
    }

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            raise HTTPException(status_code=404, detail="link not found")
    if not link["active"]:
        raise HTTPException(status_code=403, detail="link disabled")
    if is_expired(link):
        raise HTTPException(status_code=403, detail="link expired")
    async with CUSTOM_ADDRESSES_LOCK:
        addresses = list(CUSTOM_ADDRESSES)
    sub_links = []
    server_link = generate_vless_link(uid, remark=f"REN-{link['label']}-Server")
    sub_links.append(server_link)
    for i, addr in enumerate(addresses):
        remark = f"REN-{link['label']}-IP{i+1}"
        vless_link = generate_vless_link(uid, remark=remark, address=addr)
        sub_links.append(vless_link)
    sub_content = "\n".join(sub_links)
    encoded = base64.b64encode(sub_content.encode()).decode()
    
    pending = link_pending_usage.get(uid, 0)
    used = link["used_bytes"] + pending
    
    headers = {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": "attachment; filename=\"sub.txt\"",
        "profile-update-interval": "6",
        "subscription-userinfo": f"upload={used}; download=0; total={link['limit_bytes']}; expire={expiry_epoch(link)}"
    }
    return Response(content=encoded, headers=headers)

RELAY_BUF = 64 * 1024

async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small")
    pos = 0
    pos += 1; pos += 16
    addon_len = first_chunk[pos]; pos += 1; pos += addon_len
    command = first_chunk[pos]; pos += 1
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2
    addr_type = first_chunk[pos]; pos += 1
    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore"); pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")
    return command, address, port, first_chunk[pos:]

async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect": break
            data = msg.get("bytes") or (msg.get("text") or "").encode()
            if not data: continue
            size = len(data)
            
            if link_over_quota.get(link_uid, False):
                await websocket.close(code=1008, reason="quota exceeded")
                break
                
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            link_pending_usage[link_uid] += size
            
            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect: pass
    finally:
        try: writer.write_eof()
        except: pass

async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data: break
            size = len(data)
            
            if link_over_quota.get(link_uid, False):
                await websocket.close(code=1008, reason="quota exceeded")
                break
                
            connections[conn_id]["bytes"] += size
            link_pending_usage[link_uid] += size
            
            await websocket.send_bytes((b"\x00\x00" + data) if first else data)
            first = False
    except: pass

@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    writer = None
    conn_id = None
    client_ip = get_client_ip(websocket)
    try:
        async with LINKS_LOCK:
            link_data = LINKS.get(uuid)
            if link_data is None or not link_data["active"]:
                await websocket.close(code=1008, reason="link not found or disabled"); return
            if is_expired(link_data):
                await websocket.close(code=1008, reason="link expired"); return
            if link_data["limit_bytes"] > 0 and link_data["used_bytes"] >= link_data["limit_bytes"]:
                await websocket.close(code=1008, reason="quota exceeded"); return
            max_conn = link_data.get("max_connections", 0)
            
        if max_conn > 0:
            already_connected = client_ip in link_ip_map.get(uuid, set())
            if not already_connected:
                current = count_connections_for_link(uuid)
                if current >= max_conn:
                    await websocket.close(code=1008, reason="connection limit reached"); return
                    
        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect": return
        first_chunk = first_msg.get("bytes") or (first_msg.get("text") or "").encode()
        if not first_chunk: return
        
        command, address, port, initial_payload = await parse_vless_header(first_chunk)
        conn_id = secrets.token_urlsafe(8)
        connections[conn_id] = {"uuid": uuid, "ip": client_ip, "connected_at": datetime.now().isoformat(), "bytes": 0}
        connection_sockets[conn_id] = websocket
        link_ip_map[uuid].add(client_ip)
        
        size = len(first_chunk)
        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        link_pending_usage[uuid] += size
        
        reader, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout=10.0)
        if initial_payload:
            p_size = len(initial_payload)
            connections[conn_id]["bytes"] += p_size
            link_pending_usage[uuid] += p_size
            writer.write(initial_payload)
            await writer.drain()
            
        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))
        done, pending = await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending: t.cancel()
        
    except WebSocketDisconnect: pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
    finally:
        if writer:
            try: writer.close()
            except: pass
        if conn_id:
            info = connections.pop(conn_id, None)
            connection_sockets.pop(conn_id, None)
            if info:
                uid = info.get("uuid")
                ip = info.get("ip")
                if uid and ip:
                    has_other = any(c.get("uuid") == uid and c.get("ip") == ip for c in connections.values())
                    if not has_other:
                        remove_ip_from_link(uid, ip)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Vazirmatn:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#050508;--surface:rgba(20,20,20,0.85);--surface2:#1c1c1c;--border:rgba(255,255,255,0.06);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.25);--primary:#dc2626;--primary-glow:rgba(220,38,38,0.15);--error:#ef4444;--error-bg:rgba(239,68,68,0.08);--orb1:rgba(220,38,38,0.12);--orb2:rgba(153,27,27,0.1);--orb3:rgba(239,68,68,0.06)}
html[data-theme="light"]{--bg:#f8f9fa;--surface:rgba(255,255,255,0.9);--surface2:#f9fafb;--border:rgba(0,0,0,0.08);--text:rgba(0,0,0,0.88);--text2:rgba(0,0,0,0.5);--text3:rgba(0,0,0,0.25);--primary:#16a34a;--primary-glow:rgba(22,163,74,0.15);--error:#dc2626;--error-bg:rgba(220,38,38,0.06);--orb1:rgba(22,163,74,0.1);--orb2:rgba(21,128,61,0.08);--orb3:rgba(34,197,94,0.05)}
body{font-family:'Inter','Vazirmatn',sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--text);transition:background .5s,color .5s;overflow:hidden}
body[dir="rtl"]{direction:rtl;text-align:right}

.bg-canvas{position:fixed;inset:0;z-index:0;pointer-events:none}
.orb{position:absolute;border-radius:50%;filter:blur(80px);opacity:0;animation:orbFloat 20s ease-in-out infinite}
.orb-1{width:400px;height:400px;background:var(--orb1);top:-10%;left:-5%;animation-delay:0s}
.orb-2{width:350px;height:350px;background:var(--orb2);bottom:-10%;right:-5%;animation-delay:-7s}
.orb-3{width:250px;height:250px;background:var(--orb3);top:40%;left:60%;animation-delay:-14s}
@keyframes orbFloat{0%,100%{transform:translate(0,0) scale(1);opacity:0.6}25%{transform:translate(60px,-40px) scale(1.1);opacity:0.8}50%{transform:translate(-30px,50px) scale(0.9);opacity:0.5}75%{transform:translate(40px,20px) scale(1.05);opacity:0.7}}

.grid-bg{position:fixed;inset:0;z-index:0;opacity:0.03;background-image:linear-gradient(rgba(255,255,255,0.1) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.1) 1px,transparent 1px);background-size:60px 60px;pointer-events:none}

.toolbar{position:fixed;top:20px;right:20px;display:flex;gap:8px;z-index:10}
.toolbar button{width:38px;height:38px;border-radius:12px;border:1px solid var(--border);background:var(--surface);color:var(--text2);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;transition:all .3s;backdrop-filter:blur(20px)}
.toolbar button:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-2px);box-shadow:0 4px 12px var(--primary-glow)}

.login-page{width:100%;max-width:380px;padding:0 20px;position:relative;z-index:1}
.login-card{background:var(--surface);border:1px solid var(--border);border-radius:24px;padding:48px 36px 36px;position:relative;overflow:hidden;backdrop-filter:blur(40px);box-shadow:0 8px 40px rgba(0,0,0,0.15),0 0 80px var(--primary-glow);animation:cardIn .8s cubic-bezier(0.16,1,0.3,1) forwards;opacity:0;transform:translateY(30px) scale(0.96)}
@keyframes cardIn{to{opacity:1;transform:translateY(0) scale(1)}}
.login-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--primary),transparent);animation:shimmer 3s ease-in-out infinite}
@keyframes shimmer{0%,100%{opacity:0.5;transform:scaleX(0.5)}50%{opacity:1;transform:scaleX(1)}}

.brand{text-align:center;margin-bottom:36px}
.brand svg{margin-bottom:20px;filter:drop-shadow(0 0 20px var(--primary-glow));animation:logoPulse 4s ease-in-out infinite}
@keyframes logoPulse{0%,100%{transform:scale(1)}50%{transform:scale(1.05)}}
.brand h1{font-size:24px;font-weight:800;color:var(--text);letter-spacing:-0.03em;animation:fadeUp .6s .2s ease both}
.brand p{font-size:11px;color:var(--text3);margin-top:6px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;animation:fadeUp .6s .3s ease both}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

.form-group{margin-bottom:20px;animation:fadeUp .6s .4s ease both;position:relative}
.form-group label{display:block;font-size:11px;font-weight:700;color:var(--text2);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.06em}
.input-wrapper{position:relative;display:flex;align-items:center}
.form-group input{width:100%;padding:14px 44px 14px 16px;background:var(--surface2);border:1.5px solid var(--border);border-radius:12px;color:var(--text);font-size:14px;font-family:inherit;outline:none;transition:all .3s cubic-bezier(0.4,0,0.2,1)}
body[dir="rtl"] .form-group input{padding:14px 16px 14px 44px}
.form-group input:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--primary-glow),0 0 20px var(--primary-glow)}
.form-group input::placeholder{color:var(--text3)}

.eye-btn{position:absolute;right:14px;background:none;border:none;color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;padding:4px;transition:color 0.2s}
body[dir="rtl"] .eye-btn{right:auto;left:14px}
.eye-btn:hover{color:var(--text)}

.login-btn{width:100%;padding:14px;background:var(--primary);border:none;border-radius:12px;color:#fff;font-size:14px;font-weight:700;font-family:inherit;cursor:pointer;transition:all .3s cubic-bezier(0.4,0,0.2,1);position:relative;overflow:hidden;animation:fadeUp .6s .5s ease both;display:flex;align-items:center;justify-content:center;gap:8px}
.login-btn:hover{filter:brightness(1.15);transform:translateY(-2px);box-shadow:0 8px 25px var(--primary-glow)}
.login-btn:active{transform:translateY(0) scale(0.98)}
.login-btn:disabled{opacity:0.7;cursor:not-allowed;transform:none;box-shadow:none}
.spinner{animation:spin 1s linear infinite;display:none}
@keyframes spin{to{transform:rotate(360deg)}}
.login-btn.loading .spinner{display:block}

.error-msg{background:var(--error-bg);border:1px solid rgba(255,77,106,0.15);color:var(--error);padding:12px 14px;border-radius:12px;font-size:13px;display:none;margin-bottom:20px;text-align:center;font-weight:500;animation:shake .4s ease}
.error-msg.show{display:block}
@keyframes shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-6px)}40%,80%{transform:translateX(6px)}}
</style>
</head>
<body>
<div class="bg-canvas"><div class="orb orb-1"></div><div class="orb orb-2"></div><div class="orb orb-3"></div></div>
<div class="grid-bg"></div>

<div class="toolbar">
  <button id="lang-toggle" onclick="cycleLang()" title="Language">EN</button>
  <button id="theme-toggle" onclick="toggleTheme()" title="Theme">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
  </button>
</div>
<div class="login-page">
  <div class="login-card" id="login-card">
    <div class="brand">
      <svg width="64" height="64" viewBox="0 0 56 56" fill="none">
        <rect width="56" height="56" rx="16" fill="url(#logo-grad)"/>
        <circle cx="28" cy="28" r="14" stroke="#fff" stroke-width="1.5" opacity="0.3"/>
        <circle cx="28" cy="18" r="3.5" fill="#fff"/>
        <circle cx="19" cy="33" r="3.5" fill="#fff"/>
        <circle cx="37" cy="33" r="3.5" fill="#fff"/>
        <line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5" opacity="0.8"/>
        <circle cx="28" cy="28" r="2" fill="#fff" opacity="0.9"/>
        <defs><linearGradient id="logo-grad" x1="0" y1="0" x2="56" y2="56"><stop stop-color="#dc2626"/><stop offset="1" stop-color="#991b1b"/></linearGradient></defs>
      </svg>
      <h1>REN</h1>
      <p>v1.0.1</p>
    </div>
    <div class="error-msg" id="err-box"></div>
    <form id="login-form">
      <div class="form-group">
        <label data-en="Password" data-fa="رمز عبور">Password</label>
        <div class="input-wrapper">
          <input type="password" id="password" placeholder="••••••••" autofocus>
          <button type="button" class="eye-btn" id="toggle-pw" tabindex="-1">
            <svg id="eye-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
      </div>
      <button type="submit" class="login-btn" id="submit-btn">
        <svg class="spinner" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
        <span data-en="Sign In" data-fa="ورود">Sign In</span>
      </button>
    </form>
  </div>
</div>
<script>
let lang=localStorage.getItem('ren_lang')||'en';
let theme=localStorage.getItem('ren_theme')||'dark';
function setLang(l){lang=l;document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});document.getElementById('lang-toggle').textContent=l.toUpperCase();localStorage.setItem('ren_lang',l)}
function cycleLang(){setLang(lang==='en'?'fa':'en')}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('ren_theme',t)}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
applyTheme(theme);setLang(lang);

const pwInput = document.getElementById('password');
const togglePwBtn = document.getElementById('toggle-pw');
togglePwBtn.addEventListener('click', () => {
    if(pwInput.type === 'password'){
        pwInput.type = 'text';
        togglePwBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
    }else{
        pwInput.type = 'password';
        togglePwBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    }
});

document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();
  const err=document.getElementById('err-box');
  const btn=document.getElementById('submit-btn');
  err.classList.remove('show');
  btn.classList.add('loading');
  btn.disabled=true;
  try{
    const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwInput.value})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Failed');}
    location.href='/dashboard';
  }catch(e){
      err.textContent=e.message;
      err.classList.add('show');
      btn.classList.remove('loading');
      btn.disabled=false;
  }
});
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>REN Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=Vazirmatn:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
html[data-theme="dark"]{--bg:#030303;--surface:#101012;--surface2:#1a1a1c;--surface3:#27272a;--border:rgba(255,255,255,0.08);--border2:rgba(255,255,255,0.12);--text:rgba(255,255,255,0.92);--text2:rgba(255,255,255,0.5);--text3:rgba(255,255,255,0.3);--primary:#dc2626;--primary-glow:rgba(220,38,38,0.15);--primary-dim:rgba(220,38,38,0.1);--accent:#991b1b;--green:#22c55e;--green-dim:rgba(34,197,94,0.1);--red:#ef4444;--red-dim:rgba(239,68,68,0.08);--yellow:#fbbf24;--sidebar-bg:#0a0a0c;--shadow:0 4px 12px rgba(0,0,0,0.4)}
html[data-theme="light"]{--bg:#f4f4f5;--surface:#ffffff;--surface2:#f9fafb;--surface3:#f3f4f6;--border:rgba(0,0,0,0.08);--border2:rgba(0,0,0,0.12);--text:rgba(0,0,0,0.88);--text2:rgba(0,0,0,0.5);--text3:rgba(0,0,0,0.3);--primary:#16a34a;--primary-glow:rgba(22,163,74,0.15);--primary-dim:rgba(22,163,74,0.06);--accent:#15803d;--green:#16a34a;--green-dim:rgba(22,163,74,0.08);--red:#dc2626;--red-dim:rgba(220,38,38,0.08);--yellow:#d97706;--sidebar-bg:#ffffff;--shadow:0 4px 12px rgba(0,0,0,0.06)}
html,body{height:100%}
body{font-family:'Inter','Vazirmatn',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;transition:background .3s,color .3s}
body[dir="rtl"]{direction:rtl;text-align:right}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--surface3);border-radius:4px}

/* Skeleton Loading */
.skeleton { position: relative; overflow: hidden; background: var(--surface2) !important; color: transparent !important; border-color: transparent !important; pointer-events: none; border-radius: 4px; }
.skeleton::after { content: ""; position: absolute; top: 0; right: 0; bottom: 0; left: 0; transform: translateX(-100%); background: linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent); animation: shimmer 1.5s infinite; }
html[data-theme="light"] .skeleton::after { background: linear-gradient(90deg, transparent, rgba(0,0,0,0.05), transparent); }
@keyframes shimmer { 100% { transform: translateX(100%); } }

/* Tooltip */
[data-tooltip] { position: relative; }
[data-tooltip]::after { content: attr(data-tooltip); position: absolute; bottom: 100%; left: 50%; transform: translateX(-50%) translateY(4px); background: var(--surface3); color: var(--text); padding: 5px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; opacity: 0; pointer-events: none; transition: all 0.2s; white-space: nowrap; z-index: 100; border: 1px solid var(--border); box-shadow: var(--shadow); }
[data-tooltip]:hover::after { opacity: 1; transform: translateX(-50%) translateY(-8px); }
body[dir="rtl"] [data-tooltip]::after { font-family: 'Vazirmatn', sans-serif; }

.sidebar{width:240px;background:var(--sidebar-bg);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;left:0;top:0;bottom:0;z-index:100;transition:transform 0.3s cubic-bezier(0.4,0,0.2,1); backdrop-filter: blur(20px);}
body[dir="rtl"] .sidebar{left:auto;right:0;border-right:none;border-left:1px solid var(--border)}
.sidebar-brand{padding:20px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);position:relative;overflow:hidden}
.sidebar-brand-left{display:flex;align-items:center;gap:12px}
.sidebar-brand-left .brand-name{font-size:18px;font-weight:800;color:var(--text);letter-spacing:-0.02em}
.sidebar-brand-right button{width:32px;height:32px;border-radius:10px;border:1px solid var(--border);background:var(--surface2);color:var(--text3);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.sidebar-brand-right button:hover{border-color:var(--primary);color:var(--primary);transform:translateY(-1px);box-shadow:0 4px 10px var(--primary-glow)}

.sidebar-nav{flex:1;padding:12px;overflow-y:auto;display:flex;flex-direction:column;gap:4px}
.nav-section{font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.08em;padding:16px 12px 8px;margin-top:8px}
.nav-item{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:10px;color:var(--text2);font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;text-decoration:none;border:none;background:transparent;width:100%;text-align:left}
body[dir="rtl"] .nav-item{text-align:right}
.nav-item:hover{background:var(--surface2);color:var(--text)}
.nav-item.active{background:var(--primary-dim);color:var(--primary);box-shadow:inset 3px 0 0 var(--primary)}
body[dir="rtl"] .nav-item.active{box-shadow:inset -3px 0 0 var(--primary)}
.nav-icon{width:18px;height:18px;opacity:0.7}
.nav-item.active .nav-icon{opacity:1}
.nav-badge{margin-left:auto;background:var(--primary);color:#fff;font-size:10px;padding:2px 8px;border-radius:10px;font-weight:700}
body[dir="rtl"] .nav-badge{margin-left:0;margin-right:auto}

.sidebar-footer{padding:16px;border-top:1px solid var(--border)}
.sidebar-footer .footer-row{display:flex;gap:6px;margin-bottom:12px}
.sidebar-footer .footer-btn{flex:1;padding:8px;border:1px solid var(--border);border-radius:10px;background:var(--surface2);color:var(--text3);font-family:inherit;font-size:12px;font-weight:600;cursor:pointer;transition:all .2s}
.sidebar-footer .footer-btn.active{background:var(--primary);color:#fff;border-color:var(--primary)}
.sidebar-footer .footer-btn:hover:not(.active){border-color:var(--text3);color:var(--text)}
.logout-btn{width:100%;padding:10px;border:1px solid var(--border);border-radius:10px;background:none;color:var(--text3);font-family:inherit;font-size:13px;font-weight:600;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;gap:8px}
.logout-btn:hover{background:var(--red-dim);border-color:rgba(239,68,68,0.2);color:var(--red)}

.main{margin-left:240px;flex:1;padding:32px;min-height:100vh;max-width:1400px;margin-right:auto}
body[dir="rtl"] .main{margin-left:auto;margin-right:240px}
.page{display:none;animation:pageIn .4s cubic-bezier(0.16,1,0.3,1)}
.page.active{display:block}
@keyframes pageIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.page-header{margin-bottom:28px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.page-title{font-size:24px;font-weight:800;color:var(--text);letter-spacing:-0.02em}
.page-sub{font-size:13px;color:var(--text3);margin-top:6px;font-weight:500}

.stats-row{display:grid;grid-template-columns:repeat(auto-fit, minmax(220px, 1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:20px;transition:all .3s cubic-bezier(0.4,0,0.2,1);position:relative;overflow:hidden}
.stat-card:hover{box-shadow:var(--shadow);transform:translateY(-2px);border-color:var(--border2)}
.stat-label{font-size:12px;color:var(--text3);font-weight:700;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:12px}
.stat-value{font-size:28px;font-weight:800;color:var(--text);letter-spacing:-0.03em}
.stat-unit{font-size:14px;font-weight:600;color:var(--text3)}

.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;margin-bottom:16px;transition:all .3s;box-shadow:0 2px 8px rgba(0,0,0,0.1)}
.card-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}
.card-title{font-size:15px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:8px}

.btn{font-family:inherit;font-size:13px;font-weight:600;border-radius:10px;padding:8px 16px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:8px;border:none;transition:all .2s;outline:none}
.btn svg{width:16px;height:16px}
.btn-primary{background:var(--primary);color:#fff;box-shadow:0 4px 12px var(--primary-glow)}
.btn-primary:hover{filter:brightness(1.1);transform:translateY(-1px)}
.btn-secondary{background:var(--surface3);color:var(--text);border:1px solid var(--border)}
.btn-secondary:hover{border-color:var(--border2);background:var(--surface2)}
.btn-danger{background:var(--red-dim);color:var(--red);border:1px solid rgba(239,68,68,0.12)}
.btn-danger:hover{background:var(--red);color:#fff}
.btn-icon{padding:6px;border-radius:8px;background:var(--surface2);border:1px solid var(--border);color:var(--text2);cursor:pointer;transition:all 0.2s}
.btn-icon:hover{background:var(--surface3);color:var(--text)}

.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}

.table-wrap{overflow-x:auto;border-radius:12px;border:1px solid var(--border);background:var(--surface)}
.table{width:100%;border-collapse:collapse}
.table th{text-align:left;font-size:12px;font-weight:700;color:var(--text3);padding:14px 16px;text-transform:uppercase;letter-spacing:0.04em;border-bottom:1px solid var(--border);background:var(--surface2)}
body[dir="rtl"] .table th{text-align:right}
.table td{padding:14px 16px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle;color:var(--text)}
.table tr:last-child td{border-bottom:none}
.table tbody tr:hover td{background:var(--surface2)}
.row-disabled{opacity:0.5;filter:grayscale(60%)}
.row-disabled:hover{opacity:0.7;filter:grayscale(0)}

.tag{display:inline-flex;align-items:center;padding:4px 10px;border-radius:6px;font-size:11px;font-weight:700;letter-spacing:0.03em;text-transform:uppercase}
.tag-vless{background:var(--primary-dim);color:var(--primary)}
.tag-active{background:var(--green-dim);color:var(--green)}
.tag-disabled{background:var(--red-dim);color:var(--red)}

.usage-pill{display:flex;align-items:center;gap:10px;padding:6px 12px;border-radius:999px;background:var(--surface2);border:1px solid var(--border);font-size:12px;color:var(--text2)}
.usage-pill .used{color:var(--text);font-weight:700}
.usage-pill .bar{flex:1;height:6px;background:var(--surface3);border-radius:3px;min-width:60px;overflow:hidden}
.usage-pill .fill{height:100%;border-radius:3px;transition:width .4s cubic-bezier(0.4,0,0.2,1)}
.usage-pill .limit{color:var(--text3);font-weight:600}

.toggle{width:38px;height:20px;border-radius:10px;background:var(--surface3);position:relative;cursor:pointer;transition:all .3s;border:1px solid var(--border)}
.toggle::after{content:'';position:absolute;width:14px;height:14px;border-radius:50%;background:var(--text3);top:2px;left:2px;transition:all .3s}
.toggle.on{background:var(--green);border-color:var(--green);box-shadow:0 0 12px rgba(34,197,94,0.3)}
.toggle.on::after{left:20px;background:#fff}

.sys-bar{height:8px;background:var(--surface3);border-radius:4px;overflow:hidden;margin-top:10px}
.sys-bar-fill{height:100%;border-radius:4px;transition:width .5s cubic-bezier(0.4,0,0.2,1)}

.status-item{display:flex;align-items:center;justify-content:space-between;padding:14px 0;border-bottom:1px solid var(--border)}
.status-item:last-child{border-bottom:none}
.status-key{color:var(--text3);font-size:13px;font-weight:600}
.status-val{color:var(--text);font-weight:700;font-size:14px}

.form-group{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
.form-label{font-size:12px;font-weight:700;color:var(--text2);text-transform:uppercase;letter-spacing:0.04em}
.form-input,.form-select{padding:12px 14px;border-radius:10px;border:1px solid var(--border);font-family:inherit;font-size:14px;outline:none;color:var(--text);background:var(--surface2);transition:all .2s}
.form-input:focus,.form-select:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);background:var(--surface)}
.form-input.error-border{border-color:var(--red) !important;box-shadow:0 0 0 3px rgba(239,68,68,0.15) !important}
.form-row{display:flex;gap:12px;flex-wrap:wrap;align-items:flex-start}
.form-row .form-group{margin-bottom:0;flex:1;min-width:120px}

/* Dropdown Styles */
.dropdown { position: relative; display: inline-block; }
.dropdown-content { position: absolute; right: 0; top: calc(100% + 4px); min-width: 160px; background: var(--surface); border: 1px solid var(--border2); border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.2); opacity: 0; visibility: hidden; transform: translateY(10px); transition: all 0.2s cubic-bezier(0.16,1,0.3,1); z-index: 50; padding: 6px; backdrop-filter: blur(10px); }
body[dir="rtl"] .dropdown-content { right: auto; left: 0; }
.dropdown-content.show { opacity: 1; visibility: visible; transform: translateY(0); }
.dropdown-item { padding: 10px 12px; display: flex; align-items: center; gap: 10px; font-size: 13px; font-weight: 600; color: var(--text2); cursor: pointer; transition: all 0.2s; border-radius: 8px; border:none; background:transparent; width:100%; text-align:left; font-family:inherit }
body[dir="rtl"] .dropdown-item { text-align:right }
.dropdown-item svg { width: 16px; height: 16px; }
.dropdown-item:hover { background: var(--surface2); color: var(--text); }
.dropdown-item.danger { color: var(--red); }
.dropdown-item.danger:hover { background: var(--red-dim); }

.empty{text-align:center;padding:60px 20px;color:var(--text3);display:flex;flex-direction:column;align-items:center;gap:12px}
.empty-icon{color:var(--border2)}

.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(20px);background:var(--surface);color:var(--text);border:1px solid var(--border2);border-radius:12px;padding:12px 24px;font-size:13px;font-weight:600;opacity:0;transition:all .3s cubic-bezier(0.4,0,0.2,1);z-index:999;display:flex;align-items:center;gap:10px;box-shadow:0 12px 32px rgba(0,0,0,0.3)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.error{border-color:var(--red-dim);color:var(--red);background:rgba(239,68,68,0.05)}

.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:200;display:none;align-items:center;justify-content:center;backdrop-filter:blur(8px);opacity:0;transition:opacity 0.3s}
.modal-overlay.show{display:flex;opacity:1}
.modal{background:var(--surface);border:1px solid var(--border2);border-radius:20px;padding:28px;width:100%;max-width:440px;position:relative;box-shadow:0 24px 60px rgba(0,0,0,0.4);transform:scale(0.95) translateY(10px);transition:all .4s cubic-bezier(0.16,1,0.3,1)}
.modal-overlay.show .modal{transform:scale(1) translateY(0)}
.modal-title{font-size:18px;font-weight:800;margin-bottom:24px;color:var(--text)}
.modal-close{position:absolute;top:16px;right:16px;background:var(--surface2);border:1px solid var(--border);color:var(--text2);width:32px;height:32px;border-radius:10px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
body[dir="rtl"] .modal-close{right:auto;left:16px}
.modal-close:hover{background:var(--red-dim);color:var(--red);border-color:rgba(239,68,68,0.2)}
.qr-box{text-align:center;padding:24px;background:var(--surface2);border-radius:16px;margin-top:16px;border:1px solid var(--border);transition:all .3s}
.qr-box img{max-width:240px;border-radius:12px;border:4px solid var(--surface);box-shadow:0 8px 24px rgba(0,0,0,0.2)}

.inbounds-toolbar{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.search-box{flex:1;min-width:220px;position:relative}
.search-box input{width:100%;padding:10px 14px 10px 38px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:13px;font-family:inherit;outline:none;transition:all .2s}
body[dir="rtl"] .search-box input{padding:10px 38px 10px 14px}
.search-box input:focus{border-color:var(--primary);box-shadow:0 0 0 3px var(--primary-glow);background:var(--surface)}
.search-box svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--text3);width:16px;height:16px}
body[dir="rtl"] .search-box svg{left:auto;right:12px}
.filter-chips{display:flex;gap:4px;padding:4px;background:var(--surface2);border:1px solid var(--border);border-radius:10px}
.chip{padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600;color:var(--text2);cursor:pointer;border:none;background:none;transition:all .2s;font-family:inherit}
.chip.active{background:var(--surface3);color:var(--text);box-shadow:var(--shadow)}
.chip:hover:not(.active){color:var(--text)}

.inbound-cards{display:none;flex-direction:column;gap:12px;padding:0}
.inbound-card{border:1px solid var(--border);border-radius:16px;padding:16px;background:var(--surface);display:flex;flex-direction:column;gap:12px;transition:all 0.2s}
.inbound-card.disabled{opacity:0.6}
.inbound-card-header{display:flex;align-items:center;justify-content:space-between}
.inbound-card-id{font-size:11px;color:var(--text3);font-weight:700}
.inbound-card-name{font-size:14px;font-weight:700;color:var(--text)}

.mobile-header{display:none;position:fixed;top:0;left:0;right:0;height:56px;background:var(--sidebar-bg);border-bottom:1px solid var(--border);z-index:90;align-items:center;justify-content:space-between;padding:0 16px;backdrop-filter:blur(20px)}
.menu-toggle{width:36px;height:36px;border-radius:10px;border:1px solid var(--border);background:var(--surface2);color:var(--text);display:flex;align-items:center;justify-content:center;cursor:pointer}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:99;backdrop-filter:blur(4px);opacity:0;transition:opacity 0.3s}
.sidebar-overlay.show{display:block;opacity:1}

@media(max-width:768px){
  .sidebar{transform:translateX(-100%);width:260px;z-index:200}
  body[dir="rtl"] .sidebar{transform:translateX(100%)}
  .sidebar.open{transform:translateX(0);box-shadow:4px 0 24px rgba(0,0,0,0.5)}
  .main{margin-left:0;padding:72px 16px 32px;max-width:100%}
  body[dir="rtl"] .main{margin-right:0}
  .mobile-header{display:flex}
  .inbounds-toolbar{flex-direction:column;align-items:stretch}
  .search-box{min-width:unset}
  .filter-chips{justify-content:center}
  .table-wrap{display:none}
  .inbound-cards{display:flex}
}
</style>
</head>
<body>

<div class="toast" id="toast"></div>

<div class="mobile-header">
  <div style="display:flex;align-items:center;gap:10px">
    <svg width="24" height="24" viewBox="0 0 56 56" fill="none"><rect width="56" height="56" rx="14" fill="#dc2626"/><circle cx="28" cy="18" r="3.5" fill="#fff"/><circle cx="19" cy="33" r="3.5" fill="#fff"/><circle cx="37" cy="33" r="3.5" fill="#fff"/><line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5"/><line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5"/><line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5"/><circle cx="28" cy="28" r="2" fill="#fff"/></svg>
    <span style="font-weight:800;font-size:16px;letter-spacing:-0.02em">REN</span>
  </div>
  <button class="menu-toggle" onclick="document.getElementById('sidebar').classList.add('open');document.getElementById('sidebar-overlay').classList.add('show')">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
  </button>
</div>
<div class="sidebar-overlay" id="sidebar-overlay" onclick="document.getElementById('sidebar').classList.remove('open');this.classList.remove('show')"></div>

<aside class="sidebar" id="sidebar">
  <div class="sidebar-brand">
    <div class="sidebar-brand-left">
      <svg width="32" height="32" viewBox="0 0 56 56" fill="none"><rect width="56" height="56" rx="14" fill="#dc2626"/><circle cx="28" cy="18" r="3.5" fill="#fff"/><circle cx="19" cy="33" r="3.5" fill="#fff"/><circle cx="37" cy="33" r="3.5" fill="#fff"/><line x1="28" y1="21.5" x2="21" y2="30" stroke="#fff" stroke-width="1.5"/><line x1="28" y1="21.5" x2="35" y2="30" stroke="#fff" stroke-width="1.5"/><line x1="22.5" y1="33" x2="33.5" y2="33" stroke="#fff" stroke-width="1.5"/><circle cx="28" cy="28" r="2" fill="#fff"/></svg>
      <span class="brand-name">REN</span>
    </div>
    <div class="sidebar-brand-right">
      <button onclick="toggleTheme()" id="theme-btn" title="Toggle theme">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      </button>
    </div>
  </div>
  <nav class="sidebar-nav">
    <div class="nav-section">Main</div>
    <button class="nav-item active" data-page="dashboard">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      <span data-en="Dashboard" data-fa="داشبورد">Dashboard</span>
    </button>
    <button class="nav-item" data-page="inbounds">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
      <span data-en="Inbounds" data-fa="اینباندها">Inbounds</span>
      <span class="nav-badge skeleton" id="links-badge">0</span>
    </button>
    <button class="nav-item" data-page="traffic">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
      <span data-en="Traffic" data-fa="ترافیک">Traffic</span>
    </button>
    <button class="nav-item" data-page="addresses">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
      <span data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</span>
    </button>
    <button class="nav-item" data-page="domain">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
      <span data-en="Domain" data-fa="دامنه">Domain</span>
    </button>
    <div class="nav-section">System</div>
    <button class="nav-item" data-page="security">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
      <span data-en="Security" data-fa="امنیت">Security</span>
    </button>
  </nav>
  <div class="sidebar-footer">
    <div class="footer-row">
      <button class="footer-btn active" onclick="setLang('en')" id="lang-en">EN</button>
      <button class="footer-btn" onclick="setLang('fa')" id="lang-fa">FA</button>
    </div>
    <button class="logout-btn" onclick="fetch('/api/logout',{method:'POST'}).then(()=>location.href='/login')">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      <span data-en="Logout" data-fa="خروج">Logout</span>
    </button>
  </div>
</aside>

<main class="main">

  <section class="page active" id="page-dashboard">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Dashboard" data-fa="داشبورد">Dashboard</div>
        <div class="page-sub skeleton" id="last-update" style="min-width:120px">Updated: --</div>
      </div>
      <div style="display:flex;gap:10px">
        <button class="btn btn-secondary" onclick="quickCreate(0.5,'GB')">+ 0.5 GB</button>
        <button class="btn btn-primary" onclick="quickCreate(1,'GB')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            1 GB
        </button>
      </div>
    </div>
    <div class="stats-row">
      <div class="stat-card">
        <div class="stat-label" data-en="Traffic" data-fa="ترافیک">Traffic</div>
        <div class="stat-value skeleton" id="s-traffic">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
        <div class="stat-value skeleton" id="s-links">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Uptime" data-fa="آپتایم">Uptime</div>
        <div class="stat-value skeleton" id="s-uptime" style="font-size:22px;line-height:34px">--</div>
      </div>
      <div class="stat-card">
        <div class="stat-label" data-en="Domain" data-fa="دامنه">Domain</div>
        <div class="stat-value skeleton" id="s-domain" style="font-size:14px;word-break:break-all;line-height:34px">--</div>
      </div>
    </div>
    <div class="grid-2">
      <div class="card">
        <div class="card-header"><div class="card-title">CPU Usage</div><span class="skeleton" id="s-cpu-val" style="font-size:20px;font-weight:800;color:var(--primary)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-cpu-bar" style="width:0%;background:var(--primary)"></div></div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">Memory</div><span class="skeleton" id="s-mem-val" style="font-size:20px;font-weight:800;color:var(--green)">--%</span></div>
        <div class="sys-bar"><div class="sys-bar-fill" id="s-mem-bar" style="width:0%;background:var(--green)"></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title">Traffic Chart</div></div>
      <div style="height:220px"><canvas id="trafficChart"></canvas></div>
    </div>
  </section>

  <section class="page" id="page-inbounds">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Inbounds" data-fa="اینباندها">Inbounds</div>
        <div class="page-sub">VLESS over WebSocket</div>
      </div>
      <button class="btn btn-primary" onclick="showAddModal()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        <span data-en="Add Config" data-fa="افزودن کانفیگ">Add Config</span>
      </button>
    </div>
    <div class="inbounds-toolbar">
      <div class="search-box">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
        <input id="inbound-search" placeholder="Search by name or UUID..." oninput="handleSearchInput()">
      </div>
      <div class="filter-chips">
        <button class="chip active" onclick="setFilter('all',this)" data-en="All" data-fa="همه">All</button>
        <button class="chip" onclick="setFilter('active',this)" data-en="Active" data-fa="روشن">Active</button>
        <button class="chip" onclick="setFilter('disabled',this)" data-en="Disabled" data-fa="خاموش">Disabled</button>
      </div>
    </div>
    
    <!-- Desktop Table -->
    <div class="table-wrap">
      <table class="table">
        <thead><tr>
          <th style="width:40px">ID</th>
          <th>Remark</th>
          <th style="width:80px">Type</th>
          <th>Traffic</th>
          <th style="width:90px">IPs</th>
          <th style="width:80px">Status</th>
          <th style="width:140px;text-align:right">Actions</th>
        </tr></thead>
        <tbody id="links-tbody"></tbody>
      </table>
      <div class="empty" id="links-empty" style="display:none">
        <svg class="empty-icon" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg>
        <div data-en="No inbounds found" data-fa="کانفیگی یافت نشد">No inbounds found</div>
      </div>
    </div>
    
    <!-- Mobile Cards -->
    <div class="inbound-cards" id="inbound-cards"></div>
  </section>

  <section class="page" id="page-traffic">
    <div class="page-header"><div><div class="page-title" data-en="Traffic" data-fa="ترافیک">Traffic</div><div class="page-sub" data-en="Traffic statistics" data-fa="آمار ترافیک">Traffic statistics</div></div></div>
    <div class="card">
      <div class="card-header"><div class="card-title" data-en="Overview" data-fa="نمای کلی">Overview</div></div>
      <div class="status-item"><span class="status-key" data-en="Total Traffic" data-fa="کل ترافیک">Total Traffic</span><span class="status-val skeleton" id="t-traffic">--</span></div>
      <div class="status-item"><span class="status-key" data-en="Total Requests" data-fa="کل درخواست‌ها">Total Requests</span><span class="status-val skeleton" id="t-reqs">--</span></div>
      <div class="status-item"><span class="status-key" data-en="Uptime" data-fa="آپتایم">Uptime</span><span class="status-val skeleton" id="t-uptime">--</span></div>
    </div>
  </section>

  <section class="page" id="page-addresses">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Clean IP" data-fa="آی‌پی تمیز">Clean IP</div>
        <div class="page-sub" data-en="IPs and domains for subscription configs" data-fa="آی‌پی و دامنه‌ها برای کانفیگ‌های سابسکریپشن">IPs and domains for subscription configs</div>
      </div>
      <button class="btn btn-primary" onclick="showAddAddressModal()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
        <span data-en="Add" data-fa="افزودن">Add</span>
      </button>
    </div>
    <div class="card">
      <div class="card-header"><div class="card-title" data-en="Clean IP List" data-fa="لیست آی‌پی تمیز">Clean IP List</div></div>
      <div class="status-item" style="flex-direction:column;gap:12px;border:none">
        <div style="display:flex;justify-content:space-between;width:100%">
          <span class="status-key" style="color:var(--text3);font-size:12px">Default: www.speedtest.net</span>
        </div>
        <div id="address-list" style="display:flex;flex-direction:column;gap:8px;width:100%"></div>
      </div>
    </div>
  </section>

  <section class="page" id="page-domain">
    <div class="page-header">
      <div>
        <div class="page-title" data-en="Domain" data-fa="دامنه">Domain</div>
        <div class="page-sub" data-en="Replace Render domain in configs with your custom domain" data-fa="جایگزینی دامنه رندر با دامنه اختصاصی در کانفیگ‌ها">Replace Render domain in configs with your custom domain</div>
      </div>
    </div>
    <div class="card" style="max-width:560px">
      <div class="card-header"><div class="card-title" data-en="Custom Domain" data-fa="دامنه اختصاصی">Custom Domain</div></div>
      <div id="domain-current" style="margin-bottom:20px">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:16px;background:var(--surface2);border:1px solid var(--border);border-radius:12px">
          <div style="display:flex;align-items:center;gap:12px">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--primary)"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
            <div>
              <div style="font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:0.05em" data-en="Current Domain" data-fa="دامنه فعلی">Current Domain</div>
              <div id="domain-value" class="skeleton" style="font-size:15px;font-weight:700;color:var(--text);margin-top:4px;font-family:monospace">--</div>
            </div>
          </div>
          <button class="btn btn-danger btn-sm" onclick="clearDomain()" style="display:none;padding:6px 12px" id="domain-clear-btn" data-en="Clear" data-fa="پاک کردن">Clear</button>
        </div>
      </div>
      <div style="padding:16px;background:var(--surface2);border:1px solid var(--border);border-radius:12px;margin-bottom:16px">
        <div style="font-size:12px;font-weight:700;color:var(--text3);margin-bottom:8px;text-transform:uppercase;letter-spacing:0.04em" data-en="Render Default Domain" data-fa="دامنه پیش‌فرض رندر">Render Default Domain</div>
        <div id="render-domain" class="skeleton" style="font-size:14px;font-weight:600;color:var(--text2);font-family:monospace">--</div>
      </div>
      <div class="form-group">
        <label class="form-label" data-en="New Domain" data-fa="دامنه جدید">New Domain</label>
        <div style="display:flex;gap:10px">
          <input class="form-input" id="domain-input" placeholder="example.com" style="flex:1" onkeypress="if(event.key==='Enter') saveDomain()">
          <button class="btn btn-primary" onclick="saveDomain()" data-en="Save" data-fa="ذخیره">Save</button>
        </div>
      </div>
      <div style="margin-top:16px;padding:12px 16px;background:var(--primary-dim);border:1px solid rgba(220,38,38,0.15);border-radius:10px">
        <div style="font-size:12px;font-weight:500;color:var(--text2);line-height:1.6" data-en="Set a custom domain to replace the Render domain in all VLESS configs. Make sure your domain points to this service via CNAME or A record." data-fa="دامنه اختصاصی تنظیم کنید تا دامنه رندر در تمام کانفیگ‌های VLESS جایگزین شود. مطمئن شوید دامنه شما از طریق CNAME یا A record به این سرویس اشاره می‌کند.">Set a custom domain to replace the Render domain in all VLESS configs. Make sure your domain points to this service via CNAME or A record.</div>
      </div>
    </div>
  </section>

  <section class="page" id="page-security">
    <div class="page-header"><div><div class="page-title" data-en="Security" data-fa="امنیت">Security</div><div class="page-sub" data-en="Change panel password" data-fa="تغییر رمز عبور پنل">Change panel password</div></div></div>
    <div class="card" style="max-width:440px">
      <div class="form-group">
        <label class="form-label" data-en="Current Password" data-fa="رمز عبور فعلی">Current Password</label>
        <input class="form-input" type="password" id="cur-pw" placeholder="Enter current password" onkeypress="if(event.key==='Enter') changePassword()">
      </div>
      <div class="form-group">
        <label class="form-label" data-en="New Password" data-fa="رمز عبور جدید">New Password</label>
        <input class="form-input" type="password" id="new-pw" placeholder="Min 4 characters" onkeypress="if(event.key==='Enter') changePassword()">
      </div>
      <button class="btn btn-primary" onclick="changePassword()" style="margin-top:8px" data-en="Update Password" data-fa="بروزرسانی رمز عبور">Update Password</button>
    </div>
  </section>
</main>

<!-- Modals -->
<div class="modal-overlay" id="add-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#add-modal').classList.remove('show')"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    <div class="modal-title" data-en="Add Config" data-fa="افزودن کانفیگ">Add Config</div>
    <div class="form-group">
      <label class="form-label" data-en="Remark" data-fa="نام کانفیگ">Remark</label>
      <input class="form-input" id="new-label" placeholder="e.g. User 1" onkeypress="if(event.key==='Enter') createLink()">
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label>
        <input class="form-input" id="new-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited" onkeypress="if(event.key==='Enter') createLink()">
      </div>
      <div class="form-group" style="min-width:80px;max-width:100px">
        <label class="form-label" data-en="Unit" data-fa="واحد">Unit</label>
        <select class="form-select" id="new-unit"><option value="GB">GB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label" data-en="Max IPs" data-fa="حداکثر کاربر">Max IPs</label>
      <input class="form-input" id="new-maxconn" type="number" min="0" step="1" placeholder="0 = Unlimited" onkeypress="if(event.key==='Enter') createLink()">
    </div>
    <button class="btn btn-primary" onclick="createLink()" style="width:100%;margin-top:16px" data-en="Create" data-fa="ساختن">Create</button>
  </div>
</div>

<div class="modal-overlay" id="edit-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#edit-modal').classList.remove('show')"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    <div class="modal-title" id="edit-title" data-en="Edit Config" data-fa="ویرایش کانفیگ">Edit Config</div>
    <input type="hidden" id="edit-uid">
    <div class="form-group">
      <label class="form-label" data-en="Remark" data-fa="نام کانفیگ">Remark</label>
      <input class="form-input" id="edit-name" readonly style="opacity:0.6;cursor:not-allowed">
    </div>
    <div class="form-row">
      <div class="form-group" style="flex:1">
        <label class="form-label" data-en="Traffic Limit" data-fa="محدودیت ترافیک">Traffic Limit</label>
        <input class="form-input" id="edit-limit" type="number" min="0" step="0.1" placeholder="0 = Unlimited" onkeypress="if(event.key==='Enter') saveEdit()">
      </div>
      <div class="form-group" style="min-width:80px;max-width:100px">
        <label class="form-label" data-en="Unit" data-fa="واحد">Unit</label>
        <select class="form-select" id="edit-unit"><option value="GB">GB</option></select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label" data-en="Max IPs" data-fa="حداکثر کاربر">Max IPs</label>
      <input class="form-input" id="edit-maxconn" type="number" min="0" step="1" placeholder="0 = Unlimited" onkeypress="if(event.key==='Enter') saveEdit()">
    </div>
    <div style="display:flex;gap:12px;margin-top:20px">
      <button class="btn btn-primary" onclick="saveEdit()" style="flex:1" data-en="Save" data-fa="ذخیره">Save</button>
      <button class="btn btn-secondary" onclick="$('#edit-modal').classList.remove('show')" data-en="Cancel" data-fa="لغو">Cancel</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="qr-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#qr-modal').classList.remove('show')"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    <div class="modal-title" data-en="QR Code" data-fa="کد QR">QR Code</div>
    <div class="qr-box"><img id="qr-img" src="" alt="QR"></div>
    <div style="margin-top:20px;display:flex;gap:10px;justify-content:center">
      <button class="btn btn-primary" onclick="downloadQR()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        <span data-en="Download" data-fa="دانلود">Download</span>
      </button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="add-address-modal" onclick="if(event.target===this)this.classList.remove('show')">
  <div class="modal">
    <button class="modal-close" onclick="$('#add-address-modal').classList.remove('show')"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
    <div class="modal-title" data-en="Add Clean IP" data-fa="افزودن آی‌پی تمیز">Add Clean IP</div>
    <div class="form-group">
      <label class="form-label" data-en="IPs or Domains (one per line)" data-fa="آی‌پی یا دامنه (هر خط یکی)">IPs or Domains (one per line)</label>
      <textarea class="form-input" id="new-address" rows="5" placeholder="8.8.8.8&#10;example.com&#10;1.0.0.1" style="resize:vertical;font-family:monospace"></textarea>
    </div>
    <button class="btn btn-primary" onclick="addAddresses()" style="width:100%;margin-top:16px" data-en="Add All" data-fa="افزودن همه">Add All</button>
  </div>
</div>

<script>
// SVG Icons
const ICONS = {
    copy: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`,
    check: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
    qr: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>`,
    edit: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>`,
    trash: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
    sub: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>`,
    more: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"></circle><circle cx="12" cy="5" r="1"></circle><circle cx="12" cy="19" r="1"></circle></svg>`,
    reset: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>`
};

let lang=localStorage.getItem('ren_lang')||'en';
let theme=localStorage.getItem('ren_theme')||'dark';
let allLinks=[];let currentFilter='all';let statsData={};let trafficChart=null;

const $=s=>document.querySelector(s);
const $$=s=>document.querySelectorAll(s);

function setLang(l){lang=l;document.getElementById('lang-en').classList.toggle('active',l==='en');document.getElementById('lang-fa').classList.toggle('active',l==='fa');document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});localStorage.setItem('ren_lang',l)}
function applyTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('ren_theme',t);const btn=$('#theme-btn');if(btn)btn.innerHTML=t==='dark'?'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>':'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>'}
function toggleTheme(){applyTheme(theme==='dark'?'light':'dark')}
function showAddModal(){validateInput($('#new-label'), true);$('#new-label').value='';$('#new-limit').value='';$('#new-maxconn').value='';$('#add-modal').classList.add('show');setTimeout(()=>$('#new-label').focus(),100)}

function setFilter(f,el){currentFilter=f;$$('.chip').forEach(c=>c.classList.remove('active'));el.classList.add('active');filterInbounds()}

let searchTimeout;
function handleSearchInput(){
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(filterInbounds, 300);
}

function filterInbounds(){const q=($('#inbound-search')?.value||'').toLowerCase();let filtered=allLinks;if(currentFilter==='active')filtered=filtered.filter(l=>l.active);if(currentFilter==='disabled')filtered=filtered.filter(l=>!l.active);if(q)filtered=filtered.filter(l=>l.label.toLowerCase().includes(q)||l.uuid.toLowerCase().includes(q));renderLinks(filtered)}
function fmtBytes(b){return b>1073741824?(b/1073741824).toFixed(2)+' GB':b>1048576?(b/1048576).toFixed(2)+' MB':(b/1024).toFixed(1)+' KB'}
function fmtLimit(b){if(b===0)return'∞';const gb=b/1073741824;return(gb%1===0?gb.toFixed(0):gb.toFixed(1))+' GB'}

$$('.nav-item').forEach(el=>el.addEventListener('click',()=>switchPage(el.dataset.page)));
function switchPage(id){$$('.page').forEach(p=>p.classList.remove('active'));$(`#page-${id}`)?.classList.add('active');$$('.nav-item').forEach(n=>n.classList.toggle('active',n.dataset.page===id));$('#sidebar').classList.remove('open');$('#sidebar-overlay').classList.remove('show')}
function toast(msg,err=false){const t=$('#toast');t.innerHTML=err?`<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>${msg}`:`<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>${msg}`;t.className='toast'+(err?' error':'')+' show';setTimeout(()=>t.classList.remove('show'),3000)}
function esc(s){return s.replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}

function removeSkeletons() {
    $$('.skeleton').forEach(el => el.classList.remove('skeleton'));
}

async function loadStats(){
  try{
    const r=await fetch('/stats');if(!r.ok)throw new Error();statsData=await r.json();
    removeSkeletons();
    
    const pulse=(el,val)=>{if(el.textContent!==val){el.style.transition='color .2s';el.style.color='var(--primary)';el.textContent=val;setTimeout(()=>el.style.color='',400)}};
    $('#s-traffic').innerHTML=statsData.total_traffic_mb+'<span class="stat-unit"> MB</span>';
    pulse($('#s-links'),statsData.links_count);
    pulse($('#s-uptime'),statsData.uptime);
    pulse($('#s-domain'),statsData.domain);
    $('#links-badge').textContent=statsData.links_count;
    $('#last-update').textContent=(lang==='fa'?'بروزرسانی: ':'Updated: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');
    if($('#t-traffic'))$('#t-traffic').textContent=statsData.total_traffic_mb+' MB';
    if($('#t-reqs'))$('#t-reqs').textContent=statsData.total_requests.toLocaleString();
    if($('#t-uptime'))$('#t-uptime').textContent=statsData.uptime;
    
    if(statsData.cpu_percent!==undefined){const c=statsData.cpu_percent;const cc=c>80?'var(--red)':c>50?'var(--yellow)':'var(--primary)';$('#s-cpu-val').textContent=c.toFixed(1)+'%';$('#s-cpu-val').style.color=cc;$('#s-cpu-bar').style.width=c+'%';$('#s-cpu-bar').style.background=cc}
    if(statsData.memory_percent!==undefined){const m=statsData.memory_percent;const mc=m>80?'var(--red)':m>50?'var(--yellow)':'var(--green)';$('#s-mem-val').textContent=m.toFixed(1)+'%';$('#s-mem-val').style.color=mc;$('#s-mem-bar').style.width=m+'%';$('#s-mem-bar').style.background=mc}
    
    updateChart();
    loadDomain();
  }catch(e){}
}

async function loadLinks(){try{const r=await fetch('/api/links');if(!r.ok)throw new Error();const d=await r.json();allLinks=d.links||[];filterInbounds();}catch(e){}}

function toggleDropdown(e, id) {
    e.stopPropagation();
    $$('.dropdown-content.show').forEach(el => { if(el.id !== id) el.classList.remove('show'); });
    document.getElementById(id).classList.toggle('show');
}
window.addEventListener('click', () => {
    $$('.dropdown-content.show').forEach(el => el.classList.remove('show'));
});

async function copyWithFeedback(text, btnElement) {
    try {
        await navigator.clipboard.writeText(text);
        const originalHTML = btnElement.innerHTML;
        btnElement.innerHTML = ICONS.check;
        btnElement.style.color = 'var(--green)';
        btnElement.style.borderColor = 'var(--green)';
        setTimeout(() => {
            btnElement.innerHTML = originalHTML;
            btnElement.style.color = '';
            btnElement.style.borderColor = '';
        }, 2000);
    } catch (e) { toast('Failed to copy', true); }
}

async function copySubLinkWithFeedback(uid, btnElement) {
    try {
        const domain = location.host;
        const subUrl = `https://${domain}/sub/${uid}`;
        await navigator.clipboard.writeText(subUrl);
        const originalHTML = btnElement.innerHTML;
        btnElement.innerHTML = ICONS.check + (btnElement.innerText.includes('Sub') ? ' Copied' : '');
        btnElement.style.color = 'var(--green)';
        setTimeout(() => {
            btnElement.innerHTML = originalHTML;
            btnElement.style.color = '';
        }, 2000);
    } catch (e) { toast('Failed to copy', true); }
}

function renderLinks(links){
  const tbody=$('#links-tbody');const empty=$('#links-empty');const cards=$('#inbound-cards');
  if(!links.length){tbody.innerHTML='';cards.innerHTML='';empty.style.display='flex';return;}
  empty.style.display='none';
  let idx=links.length;
  
  const rows=links.map(l=>{
    const u=l.used_bytes,lim=l.limit_bytes;
    const uF=fmtBytes(u);const lF=fmtLimit(lim);
    const pct=lim>0?Math.min(100,(u/lim)*100):0;
    const col=pct>90?'var(--red)':pct>70?'var(--yellow)':'var(--primary)';
    const i=idx--;
    const rowClass = l.active ? '' : 'row-disabled';
    const cardClass = l.active ? '' : 'disabled';
    
    return {l,uF,lF,pct,col,i,maxConn:l.max_connections||0,curConn:l.current_connections||0, rowClass, cardClass};
  });
  
  tbody.innerHTML=rows.map(r=>`<tr class="${r.rowClass}">
    <td style="color:var(--text3);font-size:12px;font-weight:700">#${r.i}</td>
    <td style="font-weight:700;font-size:14px">${esc(r.l.label)}</td>
    <td><span class="tag tag-vless">VLESS</span></td>
    <td><div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div></td>
    <td style="font-size:13px;font-weight:700;color:${r.maxConn>0&&r.curConn>=r.maxConn?'var(--red)':'var(--text2)'}">${r.curConn}/${r.maxConn||'∞'}</td>
    <td><span class="tag ${r.l.active?'tag-active':'tag-disabled'}">${r.l.active?'On':'Off'}</span></td>
    <td style="text-align:right">
      <div style="display:flex;gap:6px;align-items:center;justify-content:flex-end">
        <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)" data-tooltip="${r.l.active?'Disable':'Enable'}"></button>
        <button class="btn-icon" onclick="copyWithFeedback('${esc(r.l.vless_link)}', this)" data-tooltip="Copy Config">${ICONS.copy}</button>
        <button class="btn-icon" onclick="showQRText('${esc(r.l.vless_link)}')" data-tooltip="QR Code">${ICONS.qr}</button>
        
        <div class="dropdown">
            <button class="btn-icon" onclick="toggleDropdown(event, 'drop-${r.l.uuid}')">${ICONS.more}</button>
            <div class="dropdown-content" id="drop-${r.l.uuid}">
                <button class="dropdown-item" onclick="showEditModal('${r.l.uuid}')">${ICONS.edit} Edit</button>
                <button class="dropdown-item" onclick="copySubLinkWithFeedback('${r.l.uuid}', this)">${ICONS.sub} Copy Sub URL</button>
                <button class="dropdown-item" onclick="resetUsage('${r.l.uuid}')">${ICONS.reset} Reset Traffic</button>
                <div style="height:1px;background:var(--border);margin:4px 0"></div>
                <button class="dropdown-item danger" onclick="deleteLink('${r.l.uuid}')">${ICONS.trash} Delete</button>
            </div>
        </div>
      </div>
    </td>
  </tr>`).join('');

  cards.innerHTML=rows.map(r=>`<div class="inbound-card ${r.cardClass}">
    <div class="inbound-card-header">
      <div style="display:flex;align-items:center;gap:10px">
        <span class="inbound-card-id">#${r.i}</span>
        <span class="inbound-card-name">${esc(r.l.label)}</span>
        <span class="tag tag-vless">VLESS</span>
      </div>
      <button class="toggle ${r.l.active?'on':''}" data-uid="${r.l.uuid}" onclick="toggleLink(this)"></button>
    </div>
    <div class="usage-pill"><span class="used">${r.uF}</span><div class="bar"><div class="fill" style="width:${r.pct}%;background:${r.col}"></div></div><span class="limit">${r.lF}</span></div>
    <div style="display:flex;align-items:center;justify-content:space-between">
        <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--text2)"><span style="font-weight:700;color:${r.maxConn>0&&r.curConn>=r.maxConn?'var(--red)':'var(--text)'}">${r.curConn}/${r.maxConn||'∞'}</span> <span>IPs connected</span></div>
        <div style="display:flex;gap:6px;align-items:center">
            <button class="btn-icon" onclick="copyWithFeedback('${esc(r.l.vless_link)}', this)">${ICONS.copy}</button>
            <button class="btn-icon" onclick="showQRText('${esc(r.l.vless_link)}')">${ICONS.qr}</button>
            <div class="dropdown">
                <button class="btn-icon" onclick="toggleDropdown(event, 'drop-card-${r.l.uuid}')">${ICONS.more}</button>
                <div class="dropdown-content" id="drop-card-${r.l.uuid}">
                    <button class="dropdown-item" onclick="showEditModal('${r.l.uuid}')">${ICONS.edit} Edit</button>
                    <button class="dropdown-item" onclick="copySubLinkWithFeedback('${r.l.uuid}', this)">${ICONS.sub} Copy Sub URL</button>
                    <button class="dropdown-item" onclick="resetUsage('${r.l.uuid}')">${ICONS.reset} Reset Traffic</button>
                    <div style="height:1px;background:var(--border);margin:4px 0"></div>
                    <button class="dropdown-item danger" onclick="deleteLink('${r.l.uuid}')">${ICONS.trash} Delete</button>
                </div>
            </div>
        </div>
    </div>
  </div>`).join('');
}

async function toggleLink(el){
  const uid=el.dataset.uid;
  const link=allLinks.find(l=>l.uuid===uid);
  if(!link)return;
  const newActive=!link.active;
  try{
    await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:newActive})});
    link.active=newActive;
    filterInbounds();
    loadStats();
  }catch(e){}
}

async function quickCreate(limit,unit){
  const names=['Alpha','Beta','Gamma','Delta','Echo','Zeta','Nova','Orion','Pulsar','Quasar'];
  const name=names[Math.floor(Math.random()*names.length)]+'-'+Math.floor(Math.random()*1000);
  try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:name,limit_value:limit,limit_unit:unit})});if(!r.ok)throw new Error();toast('Created: '+name);await loadLinks();await loadStats();}catch(e){toast('Error',true)}
}

function validateInput(el, reset=false){
    if(reset) { el.classList.remove('error-border'); return true; }
    if(!el.value.trim()){
        el.classList.add('error-border');
        return false;
    }
    el.classList.remove('error-border');
    return true;
}

async function createLink(){
  const labelEl=$('#new-label');
  if(!validateInput(labelEl)) return;
  const label=labelEl.value.trim();
  const val=parseFloat($('#new-limit').value)||0;const unit='GB';const maxconn=parseInt($('#new-maxconn').value)||0;
  if(!/^[a-zA-Z0-9\-_. ]+$/.test(label)){labelEl.classList.add('error-border');toast('Only English letters, numbers, and - _ . allowed',true);return;}
  try{const r=await fetch('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label,limit_value:val,limit_unit:unit,max_connections:maxconn})});if(!r.ok)throw new Error();toast('Config Created');$('#new-label').value='';$('#new-limit').value='';$('#new-maxconn').value='';$('#add-modal').classList.remove('show');await loadLinks();await loadStats();}catch(e){toast('Error',true)}
}

async function resetUsage(uid){
    if(!confirm(lang==='fa'?'آیا از صفر کردن ترافیک اطمینان دارید؟':'Reset traffic usage to zero?'))return;
    try{await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({reset_usage:true})});toast('Traffic Reset');await loadLinks();}catch(e){}
}

async function deleteLink(uid){
    if(!confirm(lang==='fa'?'آیا از حذف این کانفیگ اطمینان دارید؟':'Delete this inbound?'))return;
    try{await fetch(`/api/links/${uid}`,{method:'DELETE'});toast('Deleted');await loadLinks();await loadStats();}catch(e){}
}

function showEditModal(uid){
  const l=allLinks.find(x=>x.uuid===uid);if(!l)return;
  $('#edit-uid').value=uid;
  $('#edit-name').value=l.label;
  const gb=l.limit_bytes/1073741824;
  $('#edit-limit').value=l.limit_bytes>0?gb:'';
  $('#edit-unit').value='GB';
  $('#edit-maxconn').value=l.max_connections>0?l.max_connections:'';
  $('#edit-modal').classList.add('show');
  setTimeout(()=>$('#edit-limit').focus(),100);
}

async function saveEdit(){
  const uid=$('#edit-uid').value;
  const val=parseFloat($('#edit-limit').value)||0;
  const unit=$('#edit-unit').value;
  const maxconn=parseInt($('#edit-maxconn').value)||0;
  try{
    const r=await fetch(`/api/links/${uid}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({limit_value:val,limit_unit:unit,max_connections:maxconn})});
    if(!r.ok)throw new Error();
    toast('Config Updated');
    $('#edit-modal').classList.remove('show');
    await loadLinks();
  }catch(e){toast('Error',true)}
}

function showQRText(txt){if(!txt)return;$('#qr-img').src='https://api.qrserver.com/v1/create-qr-code/?size=300x300&data='+encodeURIComponent(txt);$('#qr-modal').classList.add('show');}
function downloadQR(){const img=$('#qr-img');if(!img.src)return;const a=document.createElement('a');a.href=img.src;a.download='ren-qr.png';a.click()}

async function changePassword(){
  const curEl=$('#cur-pw'); const nwEl=$('#new-pw');
  if(!validateInput(curEl) | !validateInput(nwEl)) return;
  const cur=curEl.value;const nw=nwEl.value;
  try{const r=await fetch('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error');}toast('Password Updated');curEl.value='';nwEl.value='';}catch(e){toast(e.message,true)}
}

applyTheme(theme);setLang(lang);
loadStats();loadLinks();loadAddresses();loadDomain();
setInterval(()=>{loadStats()},10000);

let allAddresses=[];

async function loadAddresses(){
  try{
    const r=await fetch('/api/addresses');
    if(!r.ok)throw new Error();
    const d=await r.json();
    allAddresses=d.addresses||[];
    renderAddresses();
  }catch(e){}
}

let currentDomain='';

async function loadDomain(){
  try{
    const r=await fetch('/api/domain');
    if(!r.ok)throw new Error();
    const d=await r.json();
    currentDomain=d.domain||'';
    const renderDomain=statsData.domain||location.host;
    $('#render-domain').textContent=renderDomain;
    if(currentDomain){
      $('#domain-value').textContent=currentDomain;
      $('#domain-value').style.color='var(--green)';
      $('#domain-clear-btn').style.display='block';
    }else{
      $('#domain-value').textContent=renderDomain+' (default)';
      $('#domain-value').style.color='var(--text2)';
      $('#domain-clear-btn').style.display='none';
    }
  }catch(e){}
}

async function saveDomain(){
  const dEl=$('#domain-input');
  if(!validateInput(dEl)) return;
  const domain=dEl.value.trim();
  try{
    const r=await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain})});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Error');}
    toast('Domain saved');
    dEl.value='';
    await loadDomain();
    await loadLinks();
  }catch(e){toast(e.message,true)}
}

async function clearDomain(){
  try{
    await fetch('/api/domain',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain:''})});
    toast('Domain cleared');
    await loadDomain();
    await loadLinks();
  }catch(e){toast('Error',true)}
}

function renderAddresses(){
  const list=$('#address-list');if(!list)return;
  if(!allAddresses.length){list.innerHTML='<div style="color:var(--text3);font-size:13px;padding:10px 0;font-weight:600">No custom addresses added</div>';return;}
  list.innerHTML=allAddresses.map((a,i)=>`
    <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--surface2);border:1px solid var(--border);border-radius:12px">
      <div style="display:flex;align-items:center;gap:12px">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text3)"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
        <div>
          <div style="font-size:14px;font-weight:700;color:var(--text);font-family:monospace">${esc(a)}</div>
          <div style="font-size:11px;color:var(--text3);font-weight:600">Address #${i+1}</div>
        </div>
      </div>
      <button class="btn-icon" onclick="deleteAddress(${i})" style="color:var(--red);background:var(--red-dim);border-color:transparent">${ICONS.trash}</button>
    </div>
  `).join('');
}

function showAddAddressModal(){$('#new-address').value='';$('#new-address').classList.remove('error-border');$('#add-address-modal').classList.add('show');setTimeout(()=>$('#new-address').focus(),100);}

async function addAddresses(){
  const tEl=$('#new-address');
  if(!validateInput(tEl)) return;
  const text=tEl.value.trim();
  const lines=text.split('\n').map(l=>l.trim()).filter(l=>l);
  let added=0;let errors=0;
  for(const addr of lines){
    if(!/^[a-zA-Z0-9\-_. ]+$/.test(addr)){errors++;continue;}
    try{
      const r=await fetch('/api/addresses',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({address:addr})});
      if(r.ok)added++;else errors++;
    }catch(e){errors++;}
  }
  if(added>0)toast(`Added ${added} address(es)`);
  if(errors>0)toast(`${errors} failed`,true);
  if(added>0){$('#add-address-modal').classList.remove('show');await loadAddresses();}
}

async function deleteAddress(index){
  if(!confirm(lang==='fa'?'آیا از حذف این آی‌پی اطمینان دارید؟':'Delete this address?'))return;
  try{
    const r=await fetch(`/api/addresses/${index}`,{method:'DELETE'});
    if(!r.ok)throw new Error();
    toast('Deleted');
    await loadAddresses();
  }catch(e){toast('Error',true)}
}

let chartLabels=[];let chartData=[];
function initChart(){
  const ctx=document.getElementById('trafficChart');if(!ctx)return;
  Chart.defaults.font.family = "'Inter', 'Vazirmatn', sans-serif";
  trafficChart=new Chart(ctx,{type:'bar',data:{labels:[],datasets:[{label:'MB',data:[],backgroundColor:'rgba(220,38,38,0.8)',hoverBackgroundColor:'#ef4444',borderRadius:6,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{backgroundColor:'rgba(20,20,20,0.9)',titleFont:{size:13},bodyFont:{size:13,weight:'bold'},padding:12,cornerRadius:8,displayColors:false}},scales:{x:{grid:{display:false},border:{display:false},ticks:{color:'rgba(255,255,255,0.4)',font:{size:11,weight:'600'}}},y:{grid:{color:'rgba(255,255,255,0.05)',drawBorder:false},border:{display:false},ticks:{color:'rgba(255,255,255,0.4)',font:{size:11,weight:'600'},callback:v=>v+' MB'},beginAtZero:true}}}});
}
initChart();
function updateChart(){
  if(!trafficChart||!statsData.hourly_traffic)return;
  const ht=statsData.hourly_traffic;
  const sorted=Object.entries(ht).sort((a,b)=>a[0].localeCompare(b[0])).slice(-12);
  const labels=sorted.map(e=>e[0]);
  const data=sorted.map(e=>Math.round(e[1]/1048576));
  trafficChart.data.labels=labels;trafficChart.data.datasets[0].data=data;
  
  const isLight = document.documentElement.getAttribute('data-theme') === 'light';
  trafficChart.options.scales.x.ticks.color = isLight ? 'rgba(0,0,0,0.4)' : 'rgba(255,255,255,0.4)';
  trafficChart.options.scales.y.ticks.color = isLight ? 'rgba(0,0,0,0.4)' : 'rgba(255,255,255,0.4)';
  trafficChart.options.scales.y.grid.color = isLight ? 'rgba(0,0,0,0.05)' : 'rgba(255,255,255,0.05)';
  
  trafficChart.update();
}
</script>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if await is_valid_session(token):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=CONFIG["port"])
