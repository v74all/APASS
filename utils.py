import logging
import asyncio
import re
import time
from typing import Optional, Dict, Any
import traceback
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
from collections import defaultdict
import statistics
import json

from rich.console import Console
from rich.logging import RichHandler

console = Console()

__all__ = ['logger', 'setup_logger', 'console', 'SecurityError', 'SecurityValidator', 'create_default_config']

logger = None

ALLOWED_COMMANDS = {
    'ls', 'pwd', 'cat', 'ps', 'netstat', 'ifconfig', 'whoami',
    'mkdir', 'touch', 'chmod',
    'stat'
}

MAX_COMMAND_LENGTH = 500
DEFAULT_TIMEOUT = 30

class SecurityError(Exception):
    pass

def setup_logger(name: str, log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    
    console_handler = RichHandler(console=console, show_time=True, show_path=False)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

    if (log_file):
        log_path = Path(log_file).resolve()
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            filename=str(log_path),
            maxBytes=5 * 1024 * 1024,
            backupCount=3
        )
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger

logger = setup_logger('utils')

async def async_run_shell_command(command: str, logger: Optional[logging.Logger] = None) -> str:
    try:
        validator = SecurityValidator()
        if not await validator.validate_command(command):
            raise SecurityError(f"Invalid command: {command}")
            
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode != 0:
            if logger:
                logger.error(f"Command failed: {stderr.decode()}")
            raise SecurityError(f"Command failed: {stderr.decode()}")
            
        return stdout.decode()
        
    except Exception as e:
        if logger:
            logger.error(f"Shell command error: {e}")
        raise SecurityError(f"Shell command error: {str(e)}")

def run_shell_command(command: str, logger: Optional[logging.Logger] = None) -> str:
    try:
        asyncio.get_running_loop()
        raise RuntimeError("run_shell_command cannot be used in an async context. Use async_run_shell_command instead.")
    except RuntimeError:
        return asyncio.run(async_run_shell_command(command, logger))

class SecurityValidator:
    
    def __init__(self):
        self.blocked_patterns = ['rm', 'mkfs', 'dd', ':|:', '>']
        self.allowed_paths = set()
        self.rate_limit_history = {}
        self.window_size = 60
        self.max_requests_per_window = 10
        self.request_history = defaultdict(list)
        self.max_requests_per_minute = 30
        self.last_validation = {}
        self.failed_attempts = {}
        self.max_failed_attempts = 3
        self.timeout = 5
        self.validation_cache = {}
        self.cache_ttl = 300
        self.max_length = 500
        self.allowed_commands = ALLOWED_COMMANDS
        self.blocked_extensions = {'.sh', '.bash', '.php', '.jsp'}
        self.blocked_dirs = {'/etc', '/var', '/usr', '/root'}
        self.port_range = {
            'min': 1024,
            'max': 65535,
            'restricted': set([3306, 5432, 6379, 27017])
        }
        self.tunnel_args = {
            'tcp', 'http', 'start', 'stop', 'status',
            '--region', '--port', '--host', '--config',
            '--log', '--metrics', '--authtoken',
            'auth', 'version', 'update', 'help'
        }

    async def validate_file_path(self, path: str) -> bool:
        logger = logging.getLogger(__name__)
        try:
            path = os.path.abspath(path)
            
            import tempfile
            self.allowed_paths.add(tempfile.gettempdir())
            
            if not os.path.exists(path):
                return True
                
            parent_dir = os.path.dirname(path)
            if any(parent_dir.startswith(allowed) for allowed in self.allowed_paths):
                return True
                
            return os.access(parent_dir, os.W_OK)
            
        except Exception as e:
            logger.error(f"File path validation error: {e}")
            return False

    async def validate_port(self, port: int) -> bool:
        try:
            if not isinstance(port, int):
                return False
                
            if not (self.port_range['min'] <= port <= self.port_range['max']):
                return False
                
            if port in self.port_range['restricted']:
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Port validation error: {e}")
            return False

    async def validate_command_cached(self, command: str) -> bool:
        cache_key = hash(command)
        now = time.time()
        
        if cache_key in self.validation_cache:
            entry = self.validation_cache[cache_key]
            if now - entry['timestamp'] < self.cache_ttl:
                return entry['result']
            
        self.validation_cache = {
            k: v for k, v in self.validation_cache.items()
            if now - v['timestamp'] < self.cache_ttl
        }
            
        result = await self.validate_command(command)
        self.validation_cache[cache_key] = {
            'result': result,
            'timestamp': now
        }
        
        return result

    def calculate_entropy(self, command: str) -> float:
        from math import log2
        
        freq = {}
        for c in command:
            freq[c] = freq.get(c, 0) + 1
            
        entropy = 0
        for f in freq.values():
            prob = f / len(command)
            entropy -= prob * log2(prob)
            
        return entropy / log2(256)

    async def validate_command(self, command: str) -> bool:
        logger = logging.getLogger(__name__)

        try:
            now = time.time()
            history = self.rate_limit_history.get(command, [])
            history = [t for t in history if now - t < self.window_size]
            self.rate_limit_history[command] = history

            if len(history) >= self.max_requests_per_window:
                raise SecurityError("Rate limit exceeded")
            
            self.rate_limit_history[command].append(now)

            now = time.time()
            user_requests = self.request_history[command]
            user_requests = [t for t in user_requests if now - t < 60]
            self.request_history[command] = user_requests
            
            if len(user_requests) >= self.max_requests_per_minute:
                raise SecurityError("Rate limit exceeded")
                
            self.request_history[command].append(now)

            now = time.time()
            if command in self.last_validation:
                if now - self.last_validation[command] < self.timeout:
                    self.failed_attempts[command] = self.failed_attempts.get(command, 0) + 1
                    if self.failed_attempts[command] >= self.max_failed_attempts:
                        logger.warning(f"Command {command} exceeded max failed attempts")
                        raise SecurityError("Maximum failed attempts exceeded.")

            if not command or len(command) > self.max_length:
                raise SecurityError(f"Command length must be between 1 and {self.max_length}.")

            cmd_lower = command.lower().strip()
            base_cmd = cmd_lower.split()[0] if cmd_lower.split() else ""

            if base_cmd in {'ngrok', 'cloudflared', 'bore', 'tunnel', 'localtunnel', 'telebit'}:
                allowed_tunnel_args = {
                    'tcp', 'http', 'start', 'stop', 'status',
                    '--region', '--port', '--host', '--config',
                    '--log', '--metrics', '--authtoken'
                }
                cmd_parts = cmd_lower.split()
                if len(cmd_parts) > 1:
                    if not any(arg in allowed_tunnel_args for arg in cmd_parts[1:]):
                        logger.warning(f"Invalid tunnel command arguments: {command}")
                        return False
                return True

            for pattern in self.blocked_patterns:
                if pattern in cmd_lower:
                    raise SecurityError(f"Command contains blocked pattern: {pattern}")

            if base_cmd not in self.allowed_commands:
                raise SecurityError(f"Command not in allowed list: {base_cmd}")

            if len(set(command)) / len(command) < 0.2:
                raise SecurityError("Suspicious command pattern detected (low entropy).")

            if any(command.endswith(ext) for ext in self.blocked_extensions):
                raise SecurityError("Blocked file extension in command.")

            if any(blocked_dir in command for blocked_dir in self.blocked_dirs):
                raise SecurityError("Access to blocked directory is not allowed.")

            unique_chars = len(set(command))
            total_chars = len(command)
            if total_chars > 0 and unique_chars / total_chars < 0.1:
                raise SecurityError("Command has suspiciously low entropy")

            if total_chars > self.max_length:
                raise SecurityError(f"Command exceeds max length of {self.max_length}")

            for pattern in self.blocked_patterns:
                if re.search(rf'\b{re.escape(pattern)}\b', command.lower()):
                    raise SecurityError(f"Command contains blocked pattern: {pattern}")

            if base_cmd == 'port':
                try:
                    port = int(cmd_lower.split()[1])
                    return await self.validate_port(port)
                except (IndexError, ValueError):
                    return False

            self.failed_attempts[command] = 0
            self.last_validation[command] = now
            return True

        except SecurityError as e:
            logger.error(f"Command validation error: {str(e)}")
            raise

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
                'echo "test"',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode != 0:
                logger.error(f"Basic command test failed: {stderr.decode()}")
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

class PerformanceMonitor:
    def __init__(self):
        self.metrics = defaultdict(list)
        
    async def measure(self, name: str, coro):
        start = time.perf_counter()
        try:
            result = await coro
            elapsed = time.perf_counter() - start
            self.metrics[name].append(elapsed)
            return result
        except Exception as e:
            self.metrics[f"{name}_errors"].append(str(e))
            raise
            
    def get_stats(self) -> Dict[str, Any]:
        return {
            name: {
                'avg': statistics.mean(times),
                'min': min(times),
                'max': max(times),
                'count': len(times)
            }
            for name, times in self.metrics.items()
            if isinstance(times[0], (int, float))
        }

perf_monitor = PerformanceMonitor()

async def async_validate_command(command: str) -> bool:
    return await SecurityValidator().validate_command(command)

async def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

def handle_exception(e: Exception) -> None:
    logger = logging.getLogger(__name__)
    error_msg = str(e)
    error_type = type(e).__name__
    stack_trace = "".join(traceback.format_tb(e.__traceback__))
    
    logger.error(
        f"Error Type: {error_type}\n"
        f"Error Message: {error_msg}\n"
        f"Stack Trace:\n{stack_trace}"
    )
    
    console.print(f"[bold red]Error[/bold red]: {error_msg}")

def create_default_config():
    default_config = {
        "tools": {
            "apksigner": {
                "v1_signing": True,
                "v2_signing": True, 
                "v3_signing": True,
                "v4_signing": False,
                "keystore": {
                    "path": None,
                    "alias": None,
                    "types": ["jks", "pkcs12"]
                }
            },
            "proguard": {
                "enabled": True,
                "rules": [
                    "-keep class * extends android.app.Activity",
                    "-keep class * extends android.app.Service",
                    "-keepattributes *Annotation*"
                ]
            },
            "default_paths": {
                "work": "work",
                "temp": "temp",
                "cache": "cache",
                "logs": "logs",
                "samples": "samples"
            },
            "security": {
                "verify_signatures": True,
                "check_integrity": True,
                "validate_manifests": True
            }
        }
    }

    config_dir = Path.home() / ".apksigner"
    config_dir.mkdir(parents=True, exist_ok=True)

    config_file = config_dir / "config.json"

    if not config_file.exists():
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)
            logger.info(f"Created default config at {config_file}")
    
    return str(config_file)

async def sync_files(src: str, dest: str, logger: Optional[logging.Logger] = None) -> bool:
    try:
        if logger:
            logger.info(f"Syncing from {src} to {dest}")
            
        validator = SecurityValidator()
        if not await validator.validate_file_path(src) or \
           not await validator.validate_file_path(dest):
            raise SecurityError("Invalid sync paths")
            
        cmd = f"rsync -av {src} {dest}"
        await async_run_shell_command(cmd, logger)
        return True
        
    except Exception as e:
        if logger:
            logger.error(f"Sync error: {e}")
        return False

def check_dependencies():
    dependencies = {
        'core': ['click', 'rich', 'asyncio'],
        'ml': ['sklearn', 'optuna', 'lightgbm'],
        'security': ['cryptography'],
        'networking': ['requests', 'aiohttp']
    }
    
    missing = {}
    
    for category, deps in dependencies.items():
        missing_in_category = []
        for dep in deps:
            try:
                __import__(dep.replace('-', '_'))
            except ImportError:
                missing_in_category.append(dep)
        
        if missing_in_category:
            missing[category] = missing_in_category
    
    return missing

def install_dependency(dependency):
    try:
        import subprocess
        import sys
        
        python_exe = sys.executable
        
        subprocess.check_call([python_exe, '-m', 'pip', 'install', dependency])
        return True, f"Successfully installed {dependency}"
    except subprocess.CalledProcessError as e:
        return False, f"Failed to install {dependency}: {str(e)}"
    except Exception as e:
        return False, f"Error installing {dependency}: {str(e)}"
