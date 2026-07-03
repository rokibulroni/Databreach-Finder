import os
import re
import json
import logging
import asyncio
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Response
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ---------------------------------------------------------
# Configuration & Logging Setup
# ---------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("professor_osint.web")

# ---------------------------------------------------------
# Pydantic Schema for Scan Configuration
# ---------------------------------------------------------
class NetworkConfig(BaseModel):
    mode: str = Field(default="direct")  # "direct", "tor", "proxy", "wireguard", "openvpn"
    proxy_url: Optional[str] = Field(default="")
    wireguard_conf: Optional[str] = Field(default="")
    openvpn_conf: Optional[str] = Field(default="")
    vpn_username: Optional[str] = Field(default="")
    vpn_password: Optional[str] = Field(default="")

class ScanConfig(BaseModel):
    query: Optional[str] = Field(default="", description="Target Domain or Company")
    username: Optional[str] = Field(default="", description="Target Username")
    extract: Optional[str] = Field(default="", description="Specific extraction type (emails, ipv4, etc.)")
    
    social_xray_url: Optional[str] = Field(default="", description="Target URL for Social X-Ray")
    
    # Toggle Modules
    tor: bool = False
    ai_analyze: bool = False
    social_xray: bool = False
    rustscan: bool = False
    harvester: bool = False
    spider: bool = False
    monitor: bool = False
    dossier: bool = False
    webcheck: bool = False
    analyzer: bool = False
    workspace: bool = False
    phone: bool = False
    awesome: bool = False
    toolbox: bool = False
    recommend: bool = False
    playbook: bool = False

# ---------------------------------------------------------
# FastAPI App Initialization
# ---------------------------------------------------------
app = FastAPI(
    title="Professor OSINT Web UI",
    description="Enterprise OSINT Intelligence Gathering via WebSockets",
    version="7.0"
)

# Add CORS Middleware for cross-origin if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("templates", exist_ok=True)

# ---------------------------------------------------------
# Network API Endpoints
# ---------------------------------------------------------
@app.get("/api/network/status")
async def network_status():
    from professor_osint.core.finder import ProfessorOSINT
    # Lightweight instance just to check network
    temp_finder = ProfessorOSINT()
    # It will automatically apply the saved network config on init
    
    config = temp_finder.get_network_config()
    ip_info = temp_finder.get_ip_info()
    
    return {
        "config": config,
        "ip_info": ip_info
    }

@app.post("/api/network/config")
async def update_network_config(config: NetworkConfig):
    from professor_osint.core.finder import ProfessorOSINT
    temp_finder = ProfessorOSINT()
    
    mode = config.mode
    proxy_url = config.proxy_url
    wg_conf = config.wireguard_conf
    ovpn_conf = config.openvpn_conf
    
    # Check for root privileges before executing VPN commands
    if mode in ["wireguard", "openvpn"]:
        import os
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            return {
                "status": "error",
                "message": "VPN connections require root privileges. Please restart the tool using: sudo professor-osint-web"
            }
            
    if mode == "wireguard" and wg_conf:
        import subprocess
        from professor_osint.constants import POSINT_VPN_DIR
        conf_path = os.path.join(POSINT_VPN_DIR, "custom.conf")
        with open(conf_path, "w") as f:
            f.write(wg_conf)
        
        try:
            subprocess.run(["wg-quick", "down", conf_path], capture_output=True)
            res = subprocess.run(["wg-quick", "up", conf_path], capture_output=True)
            if res.returncode != 0:
                logger.error(f"WireGuard error: {res.stderr.decode()}")
                return {"status": "error", "message": f"WireGuard failed: {res.stderr.decode()}"}
        except Exception as e:
            logger.error(f"Failed to run wg-quick: {e}")
            return {"status": "error", "message": f"Failed to execute wg-quick. Is wireguard-tools installed? Error: {e}"}
            
    elif mode == "openvpn" and ovpn_conf:
        import subprocess
        from professor_osint.constants import POSINT_OPENVPN_DIR
        conf_path = os.path.join(POSINT_OPENVPN_DIR, "custom.ovpn")
        with open(conf_path, "w") as f:
            f.write(ovpn_conf)
            
        try:
            # We kill any existing openvpn processes first (brute force approach for single client use)
            subprocess.run(["killall", "openvpn"], capture_output=True)
            
            cmd = ["openvpn", "--config", conf_path, "--daemon"]
            
            # Write credentials to auth.txt if provided
            if config.vpn_username and config.vpn_password:
                auth_path = os.path.join(POSINT_OPENVPN_DIR, "auth.txt")
                with open(auth_path, "w") as f:
                    f.write(f"{config.vpn_username}\n{config.vpn_password}\n")
                # Secure the auth file
                os.chmod(auth_path, 0o600)
                cmd.extend(["--auth-user-pass", auth_path])
            
            # Run OpenVPN in the background as a daemon
            res = subprocess.run(cmd, capture_output=True)
            if res.returncode != 0:
                logger.error(f"OpenVPN error: {res.stderr.decode()}")
                return {"status": "error", "message": f"OpenVPN failed: {res.stderr.decode()}"}
        except Exception as e:
            logger.error(f"Failed to run openvpn: {e}")
            return {"status": "error", "message": f"Failed to execute openvpn. Is openvpn installed? Error: {e}"}
            
    # Save the config globally
    temp_finder.save_network_config(mode, proxy_url, wg_conf, ovpn_conf)
    
    # Allow time for VPN tunnel and system routing table to establish
    if mode in ["wireguard", "openvpn"]:
        import asyncio
        await asyncio.sleep(4)
    
    # Return new status
    temp_finder.apply_network_config() # Reload
    return {
        "status": "success",
        "ip_info": temp_finder.get_ip_info()
    }

# ---------------------------------------------------------
# Serve Static Assets (HTML)
# ---------------------------------------------------------
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(content=b"", media_type="image/x-icon")

@app.get("/", response_class=HTMLResponse, summary="Serve Web Dashboard")
async def read_root():
    """Serves the main HTML dashboard for Professor OSINT."""
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(base_dir, "templates", "index.html")
        with open(template_path, "r", encoding="utf-8") as f:
            content = f.read()
        return HTMLResponse(content=content)
    except FileNotFoundError:
        logger.error(f"{template_path} not found.")
        return HTMLResponse(content="<h1>Error: Dashboard Template Not Found</h1><p>Ensure templates/index.html exists.</p>", status_code=404)

@app.get("/report/{filename}", summary="Serve Generated Reports")
async def get_report(filename: str):
    """Serve the final generated professional HTML report."""
    # Prevent directory traversal attacks
    filename = os.path.basename(filename)
    
    if not filename.endswith(".html"):
        return {"error": "Invalid file type. Only .html reports are allowed."}
        
    if os.path.exists(filename):
        return FileResponse(filename)
        
    logger.warning(f"Report requested but not found: {filename}")
    return {"error": "Report not found on the server."}

# ---------------------------------------------------------
# WebSocket Endpoint (Real-Time Scan Execution)
# ---------------------------------------------------------
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    process = None
    
    try:
        data = await websocket.receive_text()
        
        # Validate incoming data with Pydantic
        try:
            raw_config = json.loads(data)
            config = ScanConfig(**raw_config)
        except Exception as e:
            logger.error(f"Invalid configuration received: {e}")
            await websocket.send_text(json.dumps({"type": "error", "content": f"Invalid config: {e}"}))
            await websocket.close()
            return
            
        logger.info(f"Starting scan with config: {config.model_dump_json()}")
        
        # Build the OSINT command
        cmd = ["python", "professor_osint.py"]
        
        if config.query.strip():
            cmd.extend(["-q", config.query.strip()])
        if config.username.strip():
            cmd.extend(["-u", config.username.strip()])
        if config.extract.strip():
            cmd.extend(["-e", config.extract.strip()])
            
        # Map Pydantic fields to CLI flags
        flags_map = {
            "tor": "--tor",
            "ai_analyze": "--ai-analyze",
            "rustscan": "--rustscan",
            "harvester": "--harvester",
            "spider": "--spider",
            "monitor": "-m",
            "dossier": "-x",
            "webcheck": "-w",
            "analyzer": "-a",
            "workspace": "--workspace",
            "phone": "--phone",
            "awesome": "--awesome",
            "toolbox": "--toolbox",
            "recommend": "-r",
            "playbook": "-p"
        }
        
        for field, flag in flags_map.items():
            if getattr(config, field):
                cmd.append(flag)
                
        # Handle Social X-Ray specifically because it requires a URL
        if config.social_xray:
            if config.social_xray_url.strip():
                cmd.extend(["--social-xray", config.social_xray_url.strip()])
            else:
                logger.warning("Social X-Ray enabled but no URL provided. Skipping flag.")
                
        # Force HTML report generation so we can serve it back to the UI
        cmd.extend(["--report", "html"])
        
        # Set environment variable to force Rich to output ANSI color codes via pipes
        env = os.environ.copy()
        env["FORCE_COLOR"] = "1"
        
        # Spawn the scanning engine as an asynchronous subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env
        )
        
        logger.info(f"Subprocess spawned with PID: {process.pid}")
        report_pattern = re.compile(r"Professional HTML report saved to (report_.*\.html)")
        
        # Stream stdout line-by-line to the WebSocket
        while True:
            line = await process.stdout.readline()
            if not line:
                break
                
            decoded_line = line.decode('utf-8', errors='replace')
            await websocket.send_text(json.dumps({
                "type": "log",
                "content": decoded_line
            }))
            
            # Check if a report was successfully generated
            match = report_pattern.search(decoded_line)
            if match:
                report_file = match.group(1)
                await websocket.send_text(json.dumps({
                    "type": "report_ready",
                    "file": report_file
                }))
                
        # Wait for graceful termination
        await process.wait()
        logger.info(f"Subprocess {process.pid} finished with exit code {process.returncode}")
        
        await websocket.send_text(json.dumps({
            "type": "done",
            "content": f"Scan completed with exit code {process.returncode}"
        }))
        
    except WebSocketDisconnect:
        logger.warning("Client disconnected prematurely.")
        # If the client disconnects, we MUST kill the OSINT scan to prevent ghost processes
        if process and process.returncode is None:
            logger.info(f"Terminating orphaned subprocess PID {process.pid}")
            try:
                process.terminate()
                # Give it a moment to terminate gracefully, then kill
                await asyncio.sleep(1)
                if process.returncode is None:
                    process.kill()
            except ProcessLookupError:
                pass
                
    except Exception as e:
        logger.error(f"WebSocket error: {e}", exc_info=True)
        try:
            await websocket.send_text(json.dumps({
                "type": "error",
                "content": str(e)
            }))
        except:
            pass

if __name__ == "__main__":
    import uvicorn
    import socket
    
    def get_free_port(start_port=8000):
        for port in range(start_port, 9000):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(('127.0.0.1', port)) != 0:
                    return port
        return 8000

    port = get_free_port()
    logger.info(f"Starting Professor OSINT Web Server on port {port}...")
    uvicorn.run("web_app:app", host="127.0.0.1", port=port)
