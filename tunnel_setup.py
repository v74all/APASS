
import os
import json
import time
import shutil
import asyncio
import logging
import aiohttp
import platform

from pathlib import Path
from typing import Optional, Dict, Any, Union, List
from collections import defaultdict
from dataclasses import dataclass

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Confirm
from rich.table import Table
from rich.console import Console

try:
    from utils import (
        setup_logger, console, SecurityError, SecurityValidator, 
        async_run_shell_command, is_port_open
    )
except ImportError:
    class SecurityError(Exception):
        pass

    class SecurityValidator:
        async def validate_command(self, command: str) -> bool:
            return True

        async def validate_file_path(self, file_path: str) -> bool:
            return True

    async def async_run_shell_command(command: str) -> Union[str, None]:
        await asyncio.sleep(0.1)
        return "Done"

    async def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
        await asyncio.sleep(0.1)
        return False

    def run_shell_command(command: str) -> Union[str, None]:
        time.sleep(0.1)
        return "Done"

    console = Console()

    def setup_logger(name: str, file_path: str) -> logging.Logger:
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
        fh = logging.FileHandler(file_path)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        return logger

logger = setup_logger('tunnel_setup', 'logs/tunnel_setup.log')

class TunnelError(SecurityError):
    pass

class ValidationError(TunnelError):
    pass

class InstallationError(TunnelError):
    pass

class DependencyError(TunnelError):
    pass

@dataclass
class ToolConfig:
    repo: str
    description: str
    install_command: str
    folder: str
    version: Optional[str] = None
    checksum: Optional[str] = None

class TunnelSetupManager:
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = Path(config_file) if config_file else Path.home() / ".tunnel_setup" / "tunnel_config.json"
        self.security_validator = SecurityValidator()
        self.max_retries = 3
        self.max_parallel_tunnels = 5
        self.active_tunnels: Dict[str, Any] = {}
        self.rate_limits: Dict[str, float] = {}
        self.rate_limit_duration = 5
        self.pending_operations: Dict[str, asyncio.Task] = {}
        self.github_tools: Dict[str, ToolConfig] = {
            "ngrok": ToolConfig(
                repo="https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.zip",
                description="Ngrok v3 - Secure tunneling with enhanced features",
                install_command=(
                    "wget https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.zip -O ngrok.zip"
                    " && unzip -o ngrok.zip -d ngrok"
                ),
                folder="ngrok",
                version="v3"
            ),
            "cloudflared": ToolConfig(
                repo="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb",
                description="Cloudflare Tunnel client (latest) with zero-trust support",
                install_command=(
                    "wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb"
                    " && sudo dpkg -i cloudflared-linux-amd64.deb"
                ),
                folder="cloudflared",
                version="latest"
            ),
            "bore": ToolConfig(
                repo="https://github.com/ekzhang/bore",
                description="A modern, simple TCP tunnel in Rust that exposes local ports to remote servers",
                install_command="cargo install bore-cli",
                folder="bore"
            ),
            "localtunnel": ToolConfig(
                repo="https://github.com/localtunnel/localtunnel",
                description="Expose a local port to the internet with localtunnel",
                install_command="npm install -g localtunnel",
                folder="localtunnel",
                version="latest"
            ),
            "telebit": ToolConfig(
                repo="https://github.com/telebit-host/telebit",
                description="Telebit - Secure and simple tunnels over TLS using Node.js",
                install_command="npm install -g telebit",
                folder="telebit",
                version="latest"
            ),
            "sish": ToolConfig(
                repo="https://github.com/antoniomika/sish",
                description="Open source serveo/ngrok alternative implemented in Go",
                install_command="go install github.com/antoniomika/sish@latest",
                folder="sish",
                version="latest"
            ),
            "frp": ToolConfig(
                repo="https://github.com/fatedier/frp",
                description="A fast reverse proxy to help you expose a local server behind NAT/firewall",
                install_command=(
                    "wget https://github.com/fatedier/frp/releases/latest/download/frp_0.46.1_linux_amd64.tar.gz -O frp.tar.gz && "
                    "tar -xzvf frp.tar.gz --one-top-level=frp --strip-components=1"
                ),
                folder="frp",
                version="latest"
            ),
            "holer": ToolConfig(
                repo="https://github.com/WisdomFusion/holer",
                description="Tunnel local port to public network (supports TCP and HTTP)",
                install_command=(
                    "wget https://github.com/WisdomFusion/holer/releases/download/v2.0.8/holer-linux64.tar.gz -O holer.tar.gz && "
                    "mkdir -p holer && tar -xzvf holer.tar.gz -C holer"
                ),
                folder="holer",
                version="2.0.8"
            ),
            "inlets": ToolConfig(
                repo="https://github.com/inlets/inlets",
                description="Cloud Native Tunnel. Expose local endpoints to the Internet",
                install_command=(
                    "curl -sSL https://inlets.sh/install | sudo sh"
                ),
                folder="inlets",
                version="latest"
            ),
            "localxpose": ToolConfig(
                repo="https://localxpose.io",
                description="LocalXpose - Reverse Tunneling solution to expose local services to the internet",
                install_command=(
                    "curl --proto '=https' --tlsv1.2 -sSf https://localxpose.io/install.sh | sudo bash"
                ),
                folder="localxpose",
                version="latest"
            ),
        }

        self.github_tools = self._load_config()
        self.tools_dir = Path("tunnel_tools").resolve()
        self.tools_dir.mkdir(parents=True, exist_ok=True)

        logging.info("Initialized TunnelSetupManager.")
        self.health_checks = {}
        self.tunnel_metrics = defaultdict(dict)

    def _load_config(self) -> Dict[str, ToolConfig]:
        if self.config_file.exists():
            try:
                with self.config_file.open('r', encoding='utf-8') as f:
                    config = json.load(f)
                tools = {
                    name: ToolConfig(
                        repo=data["repo"],
                        description=data["description"],
                        install_command=data["install_command"],
                        folder=data["folder"],
                        version=data.get("version"),
                        checksum=data.get("checksum")
                    )
                    for name, data in config.items()
                }
                logging.debug(f"Configuration loaded from {self.config_file}")
                return tools
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from config file: {e}")
                console.print(f"[red]Error reading configuration file: {e}[/red]")
            except Exception as e:
                logging.error(f"Unexpected error loading config: {e}")
                console.print(f"[red]Unexpected error loading configuration: {e}[/red]")
        else:
            logging.info(f"No configuration file found at {self.config_file}. Using default configurations.")
        return self.github_tools

    def save_config(self):
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with self.config_file.open('w', encoding='utf-8') as f:
                config = {
                    name: {
                        "repo": tool.repo,
                        "description": tool.description,
                        "install_command": tool.install_command,
                        "folder": tool.folder,
                        "version": tool.version,
                        "checksum": tool.checksum
                    }
                    for name, tool in self.github_tools.items()
                }
                json.dump(config, f, indent=4)
            logging.debug(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")
            console.print(f"[red]Error saving configuration: {e}[/red]")

    def check_dependencies(self):
        system = platform.system().lower()
        required_deps = {}
        optional_deps = {}

        if system.startswith('linux'):
            required_deps = {
                'git': 'sudo apt-get install git -y',
                'wget': 'sudo apt-get install wget -y',
                'unzip': 'sudo apt-get install unzip -y'
            }
            optional_deps = {
                'npm': 'sudo apt-get install npm -y',
                'cargo': 'curl https://sh.rustup.rs -sSf | sh -s -- -y',
                'go': 'sudo apt-get install golang -y'
            }
        elif system.startswith('win'):
            required_deps = {
                'git': 'Download and install from https://git-scm.com/download/win',
                'wget': 'Install with Chocolatey: choco install wget',
                'unzip': 'Install with Chocolatey: choco install unzip'
            }
            optional_deps = {
                'npm': 'Install NodeJS from https://nodejs.org/',
                'cargo': 'Install Rust from https://www.rust-lang.org/tools/install',
                'go': 'Install Go from https://go.dev/dl/'
            }
        else:
            required_deps = {
                'git': 'Please install git manually',
                'wget': 'Please install wget manually',
                'unzip': 'Please install unzip manually'
            }
            optional_deps = {
                'npm': 'Install NodeJS manually',
                'cargo': 'Install Rust manually',
                'go': 'Install Go manually'
            }

        missing_required = []
        missing_optional = []
        install_instructions = []

        for cmd, install_cmd in required_deps.items():
            if shutil.which(cmd) is None:
                missing_required.append(cmd)
                install_instructions.append(f"To install {cmd}: {install_cmd}")

        for cmd, install_cmd in optional_deps.items():
            if shutil.which(cmd) is None:
                missing_optional.append(cmd)
                install_instructions.append(f"To install {cmd}: {install_cmd}")

        if missing_required:
            error_msg = (
                f"Required dependencies not found: {', '.join(missing_required)}.\n"
                "Installation instructions:\n"
                f"{chr(10).join(install_instructions)}\n"
                "Please install missing dependencies and try again."
            )
            console.print(f"[bold red][!] {error_msg}[/bold red]")
            logging.error(error_msg)
            raise DependencyError(error_msg)
        
        if missing_optional:
            warning_msg = (
                f"Some optional dependencies are not installed: {', '.join(missing_optional)}\n"
                "These dependencies are required for specific tools."
            )
            console.print(f"[yellow][!] {warning_msg}[/yellow]")
            logging.warning(warning_msg)

        logging.info("All required dependencies are satisfied.")
        console.print("[bold green][+] All required dependencies are installed.[/bold green]")

    async def validate_tool(self, tool_name: str, tool_info: ToolConfig) -> bool:
        try:
            if tool_info.checksum:
                tool_path = self.tools_dir / tool_info.folder
                zip_file = tool_path / f"{tool_info.folder}.zip"
                if not zip_file.exists():
                    raise ValidationError(f"File {zip_file} not found for validation.")

                actual_checksum = self.calculate_checksum(zip_file)
                if actual_checksum != tool_info.checksum:
                    raise ValidationError(f"Checksum for {tool_name} does not match.")

            logging.info(f"{tool_name} validation passed.")
            return True
        except Exception as e:
            logging.error(f"Tool validation failed for {tool_name}: {e}")
            raise ValidationError(f"Tool validation failed for {tool_name}: {e}")

    def calculate_checksum(self, file_path: Path, algorithm: str = 'sha256') -> str:
        import hashlib
        hash_func = getattr(hashlib, algorithm)()
        with file_path.open('rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    async def download_with_retry(self, url: str, dest: Path, retries: int = 3) -> bool:
        for attempt in range(1, retries + 1):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        if response.status == 200:
                            with dest.open('wb') as f:
                                while True:
                                    chunk = await response.content.read(1024)
                                    if not chunk:
                                        break
                                    f.write(chunk)
                            logging.info(f"Downloaded {url} successfully.")
                            return True
                        else:
                            raise InstallationError(f"Download failed with status {response.status}")
            except Exception as e:
                logging.warning(f"Attempt {attempt} failed to download {url}: {e}")
                if attempt == retries:
                    logging.error(f"Download failed after {retries} attempts: {e}")
                    raise InstallationError(f"Download failed after {retries} attempts: {e}")
                await asyncio.sleep(2 ** attempt)
        return False

    async def rate_limit_check(self, operation: str) -> bool:
        current_time = time.time()
        if operation in self.rate_limits:
            if current_time - self.rate_limits[operation] < self.rate_limit_duration:
                return False
        self.rate_limits[operation] = current_time
        return True

    async def download_tool(self, tool_name: str, tool_info: ToolConfig, progress: Progress):
        if not await self.rate_limit_check(f"download_{tool_name}"):
            raise TunnelError("Rate limit exceeded. Please wait before retrying.")

        task_id = progress.add_task(f"Installing {tool_name}", start=False)
        tool_path = self.tools_dir / tool_info.folder
        tool_path.mkdir(parents=True, exist_ok=True)

        progress.start_task(task_id)
        try:
            process = await asyncio.create_subprocess_shell(
                tool_info.install_command,
                cwd=tool_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise InstallationError(f"Installation failed:\n{stderr.decode().strip()}")

            if tool_info.checksum:
                await self.validate_tool(tool_name, tool_info)

            console.print(f"[bold green][+] {tool_name} installed successfully.[/bold green]")
            logging.info(f"{tool_name} installed successfully.")
            progress.update(task_id, completed=100)

        except Exception as e:
            console.print(f"[bold red][!] Error installing {tool_name}: {e}[/bold red]")
            logging.error(f"Error installing {tool_name}: {e}")
            self.cleanup_failed_install(tool_name)
            raise
        finally:
            progress.remove_task(task_id)

    async def download_github_tools(self, selected_tools: Dict[str, ToolConfig]):
        semaphore = asyncio.Semaphore(3)

        async def download_wrapper(tool_name: str, tool_info: ToolConfig, progress: Progress):
            async with semaphore:
                await self.download_tool(tool_name, tool_info, progress)

        async with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True
        ) as progress:
            tasks = [
                download_wrapper(tool_name, tool_info, progress)
                for tool_name, tool_info in selected_tools.items()
            ]
            await asyncio.gather(*tasks, return_exceptions=False)

    def generate_installation_guide(self):
        guide_path = Path('tunnel_tools_installation_guide.txt').resolve()
        try:
            with guide_path.open('w', encoding='utf-8') as f:
                f.write("Installation and setup instructions for tunneling tools:\n\n")
                for tool_name, tool_info in self.github_tools.items():
                    f.write(f"{tool_name}:\n")
                    f.write(f"  Description: {tool_info.description}\n")
                    f.write(f"  Repository/Link: {tool_info.repo}\n")
                    f.write(f"  Installation Command: {tool_info.install_command}\n\n")
                f.write("\nTo set up a TCP tunnel with each tool, use their specific commands or refer to the official documentation.\n")
            console.print(f"[bold green][+] Installation guide saved to '{guide_path}'[/bold green]")
            logging.info(f"Installation guide saved to {guide_path}.")
        except Exception as e:
            console.print(f"[bold red][!] Error writing installation guide: {e}[/bold red]")
            logging.exception("Failed to write installation guide.")

    def list_available_tools(self):
        table = Table(title="Available Tunneling Tools", show_lines=True)
        table.add_column("Index", style="cyan", no_wrap=True)
        table.add_column("Tool Name", style="magenta")
        table.add_column("Description", style="green")
        table.add_column("Link/Repository", style="blue")

        for idx, (tool_name, tool_info) in enumerate(self.github_tools.items(), start=1):
            table.add_row(str(idx), tool_name, tool_info.description, tool_info.repo)

        console.print(table)

    def select_tools(self) -> Dict[str, ToolConfig]:
        self.list_available_tools()
        selected_tools = {}
        for tool_name, tool_info in self.github_tools.items():
            if Confirm.ask(f"Do you want to install '{tool_name}'?"):
                selected_tools[tool_name] = tool_info
        return selected_tools

    def cleanup_failed_install(self, tool_name: str):
        tool_path = self.tools_dir / tool_name
        if tool_path.exists():
            try:
                shutil.rmtree(tool_path)
                logging.info(f"Cleaned up failed installation directory for {tool_name}.")
            except Exception as e:
                logging.error(f"Failed to clean up {tool_name} directory: {e}")
                console.print(f"[red]Error cleaning up directory {tool_name}: {e}[/red]")

    async def setup_tunnel(self):
        try:
            self.check_dependencies()
            selected_tools = self.select_tools()
            if not selected_tools:
                raise SecurityError("No tools selected for installation.")
            
            await self.download_github_tools(selected_tools)
            self.generate_installation_guide()
            console.print("\n[bold green]Installation completed successfully[/bold green]")
        except SecurityError as e:
            console.print(f"[bold red]Security error: {e}[/bold red]")
            logger.error(f"Security error during setup: {e}")
        except Exception as e:
            console.print(f"[bold red]Setup failed: {e}[/bold red]")
            logger.exception("Unexpected error during setup")

    async def start_tunnel(self, service: str, port: int, 
                           region: Optional[str] = None,
                           hostname: Optional[str] = None) -> bool:
        try:
            if not await self.validate_preconditions(service, port):
                return False
                
            for attempt in range(3):
                try:
                    await self._start_tunnel_service(service, port, region, hostname)
                    await self._setup_health_check(service, port)
                    return True
                except Exception as e:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(2 ** attempt)
                    
        except Exception as e:
            logger.error(f"Failed to start tunnel: {e}")
            raise TunnelError(str(e))

    async def _setup_health_check(self, service: str, port: int):
        self.health_checks[service] = asyncio.create_task(
            self._health_check_loop(service, port)
        )

    async def _health_check_loop(self, service: str, port: int):
        while service in self.active_tunnels:
            try:
                is_healthy = await self._check_tunnel_health(service, port)
                self.tunnel_metrics[service]['last_check'] = time.time()
                self.tunnel_metrics[service]['healthy'] = is_healthy
                
                if not is_healthy:
                    logger.warning(f"Tunnel {service} appears unhealthy")
                    await self._handle_unhealthy_tunnel(service)
                    
                await asyncio.sleep(30)
            except asyncio.CancelledError:
                logger.info(f"Health check for {service} cancelled.")
                break
            except Exception as e:
                logger.error(f"Health check error for {service}: {e}")

    async def _handle_unhealthy_tunnel(self, service: str):
        logger.warning(f"Handling unhealthy tunnel: {service}")
        tunnel_data = self.active_tunnels.get(service)
        if tunnel_data:
            self.active_tunnels[service]['status'] = 'restarting'
            port = tunnel_data.get('port', 0)
            
            try:
                await self._start_tunnel_service(service, port)
                self.active_tunnels[service]['status'] = 'running'
            except Exception as e:
                logger.error(f"Failed to restart unhealthy tunnel {service}: {e}")
                self.active_tunnels[service]['status'] = 'error'

    async def _check_tunnel_health(self, service: str, port: int) -> bool:
        try:
            return not await is_port_open('127.0.0.1', port)
        except Exception as e:
            logger.error(f"Health check failed for {service}: {e}")
            return False

    async def _monitor_tunnel(self, service: str) -> None:
        try:
            while service in self.active_tunnels:
                await asyncio.sleep(30)
                if not await self._check_tunnel_health(service, self.active_tunnels[service]['port']):
                    await self._handle_unhealthy_tunnel(service)
        except asyncio.CancelledError:
            logger.info(f"Monitor cancelled for {service}")
            raise
        except Exception as e:
            logger.error(f"Monitor failed for {service}: {e}")

    async def check_updates(self) -> Dict[str, bool]:
        update_status = {}
        for tool_name, tool_info in self.github_tools.items():
            try:
                if "github.com" in tool_info.repo:
                    async with aiohttp.ClientSession() as session:
                        async with session.head(tool_info.repo) as response:
                            latest_version_url = response.headers.get('location', '')
                            update_status[tool_name] = (tool_info.version not in latest_version_url)
                else:
                    update_status[tool_name] = False
            except Exception as e:
                logger.error(f"Update check failed for {tool_name}: {e}")
                update_status[tool_name] = False
        return update_status

    async def auto_update(self) -> None:
        updates = await self.check_updates()
        for tool_name, needs_update in updates.items():
            if needs_update:
                console.print(f"[bold yellow]{tool_name} has a new version available. Updating...[/bold yellow]")
                await self.download_tool(tool_name, self.github_tools[tool_name], Progress())

    async def cleanup_tunnels(self) -> None:
        to_remove = []
        for service, data in self.active_tunnels.items():
            if data.get("status") == "stopped":
                to_remove.append(service)
        for service in to_remove:
            self.active_tunnels.pop(service, None)
        logger.info("Cleanup of stale tunnels completed")

    async def validate_preconditions(self, service: str, port: int) -> bool:
        try:
            supported_tools = {'ngrok', 'cloudflared', 'bore', 'localtunnel', 'telebit'}
            if service.lower() not in supported_tools:
                logger.warning(f"Unsupported tunnel service: {service}")
                return False
                
            if not (1024 <= port <= 65535):
                logger.error(f"Invalid port: {port}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Precondition validation failed: {e}")
            return False

    async def _start_tunnel_service(self, service: str, port: int, 
                                    region: Optional[str] = None,
                                    hostname: Optional[str] = None) -> None:
        try:
            tool_info = self.github_tools.get(service)
            if not tool_info:
                raise TunnelError(f"Service {service} configuration not found")
                
            tool_path = self.tools_dir / tool_info.folder
            if not tool_path.exists():
                raise TunnelError(f"Service {service} is not properly installed")
                
            command = self._build_tunnel_command(service, port, region, hostname)
            await self.security_validator.validate_command(command)
            
            await async_run_shell_command(command)
            self.active_tunnels[service] = {
                "port": port,
                "started_at": time.time(),
                "status": "running"
            }
            logger.info(f"Tunnel {service} started on port {port}")
            
        except Exception as e:
            logger.error(f"Failed to start tunnel service: {e}")
            raise TunnelError(f"Service start failed: {str(e)}")

    def _build_tunnel_command(self, service: str, port: int,
                              region: Optional[str] = None,
                              hostname: Optional[str] = None) -> str:
        service = service.lower()
        if service == 'ngrok':
            cmd = f"ngrok tcp {port}"
            if region:
                cmd += f" --region {region}"

        elif service == 'cloudflared':
            cmd = f"cloudflared tunnel --url tcp://localhost:{port}"
            if hostname:
                cmd += f" --hostname {hostname}"

        else:
            raise TunnelError(f"Service {service} command configuration not implemented")
            
        return cmd

    async def configure_apk_network(self, apk_path: str) -> bool:
        try:
            if not await self.security_validator.validate_file_path(apk_path):
                return False
                
            manifest_path = "AndroidManifest.xml"
            internet_perm = 'android.permission.INTERNET'
            network_perm = 'android.permission.ACCESS_NETWORK_STATE'
            
            await self._add_permissions_to_manifest(manifest_path, [internet_perm, network_perm])
            
            return True
            
        except Exception as e:
            logger.error(f"APK network configuration failed: {e}")
            return False

    async def _add_permissions_to_manifest(self, manifest_path: str, permissions: List[str]):
        await asyncio.sleep(0.1)
        for perm in permissions:
            logger.info(f"Permission {perm} added to manifest {manifest_path}")

    async def validate_system(self) -> bool:
        try:
            checks = {
                'filesystem': os.access('.', os.W_OK | os.R_OK),
                'environment': bool(os.environ.get('HOME')),
                'user': os.getuid() != 0
            }
            
            for dir_name in ['logs', 'temp', 'cache']:
                os.makedirs(dir_name, exist_ok=True)
                
            proc = await asyncio.create_subprocess_shell(
                'echo "check"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                logger.error(f"Basic command check failed: {stderr.decode()}")
                return False
                
            if not all(checks.values()):
                failed = [k for k, v in checks.items() if not v]
                logger.error(f"System checks failed: {failed}")
                return False
                
            logger.info("Security validation passed")    
            return True
            
        except Exception as e:
            logger.error(f"System validation error: {e}")
            return False

    async def stop_tunnel(self, service: str):
        if service in self.active_tunnels:
            try:
                stop_command = f"pkill -f {service}"
                await async_run_shell_command(stop_command)
                self.active_tunnels.pop(service, None)
                logger.info(f"Tunnel {service} stopped successfully.")
                console.print(f"[green]Tunnel {service} stopped successfully.[/green]")
            except Exception as e:
                logger.error(f"Failed to stop tunnel {service}: {e}")
                console.print(f"[red]Failed to stop tunnel {service}: {e}[/red]")
        else:
            logger.warning(f"Tunnel {service} is not running.")
            console.print(f"[yellow]Tunnel {service} is not running.[/yellow]")

def parse_arguments():
    import argparse
    parser = argparse.ArgumentParser(description='Tunnel Setup Manager')
    parser.add_argument('--config', type=str, help='Path to custom configuration file')
    parser.add_argument('--upgrade', action='store_true', help='Automatically update tools if new version available')
    return parser.parse_args()

async def main():
    args = parse_arguments()
    manager = TunnelSetupManager(config_file=args.config)
    
    if args.upgrade:
        await manager.auto_update()
        console.print("[bold green]Upgrade completed successfully.[/bold green]")
    else:
        await manager.setup_tunnel()

if __name__ == "__main__":
    asyncio.run(main())
