import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger('LogReportPro.config')

class ConfigManager:
    DEFAULT_CONFIG = {
        "output_dir": "reports",
        "default_format": "pdf",
        "log_level": "INFO",
        "templates_dir": "templates",
        "security": {
            "validate_input": True,
            "validate_output": True,
        },
        "sync": {
            "enabled": False,
            "target_dir": "sync",
            "interval": 300,
            "auto_sync": False
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), 'config.json')
        self.config = self.DEFAULT_CONFIG.copy()
        self.load_config()
        self.update_from_env()
        
    def load_config(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    self._merge_configs(self.config, user_config)
                logger.info(f"Configuration loaded from {self.config_path}")
            else:
                logger.warning(f"Configuration file not found at {self.config_path}, using defaults")
                self.save_config()
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            
        Path(self.config.get("output_dir", "reports")).mkdir(parents=True, exist_ok=True)
        return self.config
        
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_configs(base[key], value)
            else:
                base[key] = value
    
    def save_config(self) -> bool:
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Configuration saved to {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value
    
    def set(self, key: str, value: Any) -> None:
        keys = key.split('.')
        config = self.config
        for i, k in enumerate(keys):
            if i == len(keys) - 1:
                config[k] = value
            else:
                if k not in config:
                    config[k] = {}
                config = config[k]

    def reload(self) -> None:
        self.load_config()
        self.update_from_env()

    def update_from_env(self) -> None:
        prefix = "LRP_"
        for env_key, env_value in os.environ.items():
            if env_key.startswith(prefix):
                config_key = env_key[len(prefix):].lower()
                config_key = config_key.replace('_', '.')
                try:
                    value = json.loads(env_value)
                except json.JSONDecodeError:
                    value = env_value
                self.set(config_key, value)
                logger.debug(f"Config override from environment: {config_key} = {value}")
