import re
import html
import json
import time
import logging
import sqlite3
import asyncio
import secrets
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Union, Set
from urllib.parse import urlparse
import jwt
from email_validator import validate_email, EmailNotValidError
import os

from utils import (
    setup_logger,
    SecurityError,
    SecurityValidator
)

logger = setup_logger('injection_manager', 'injection_manager.log')


class InjectionError(SecurityError):
    pass


class InjectionManager:
    def __init__(self, db_path: str = 'database.db', log_attacks: bool = True):
        self.security_validator = SecurityValidator()
        self.rate_limits: Dict[str, List[float]] = {}
        self.ip_rate_limits: Dict[str, Dict[str, List[float]]] = defaultdict(dict)
        self.db_path = db_path
        self.log_attacks = log_attacks
        self.attack_history: List[Dict[str, Any]] = []
        self.blocked_ips: Set[str] = set()
        self.start_time = time.time()
        self.attack_count = 0
        self.blocked_count = 0
        self._injections: Dict[str, Any] = {}
        self.patterns = {
            'sql': [
                r"(\s*([\0\b\'\"\n\r\t\%\_\\]*\s*(((select\s*.+\s*from\s*.+)|(insert\s*.+\s*into\s*.+)|(update\s*.+\s*set\s*.+)|(delete\s*.+\s*from\s*.+)|(drop\s*.+)|(truncate\s*.+)|(alter\s*.+)|(exec\s*.+)|(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s*.+[\=\>\<=\!\~]+.+)|(let\s+.+[\=]\s*.+)|(begin\s*.*\s*end)|(\s*[\/\*]+\s*.*\s*[\*\/]+)|(\s*(\-\-)\s*.*\s+)|(\s*(contains|containsall|containskey)\s+.*)))(\s*[\;]\s*)*)+))",
            ],
            'xss': [
                r"<[^>]*script.*?>",
            ],
            'file': [
                r"\.\.\/",
            ],
            'shell': [
                r";\s*\w+",
            ],
            'nosql': [
                r"\$where\s*:",
            ],
            'template': [
                r"\{\{\s*\w+\s*\}\}",
            ],
            'xml': [
                r"<!\[CDATA\[.*?\]\]>",
            ],
            'ldap': [
                r"\*\)",
            ],
            'command': [
                r";.*?;",
            ]
        }
        self.config = {
            "sanitize_level": "high",
            "log_level": "info",
            "block_after_attempts": 5,
            "block_duration": 3600,
            "trusted_domains": ["localhost", "127.0.0.1"],
            "ml_detection_enabled": False,
            "ml_threshold": 0.8,
            "enable_security_checks": {
                "sql_validation": True,
                "xss_validation": True,
                "file_inclusion_check": True,
                "ldap_validation": True,
                "xml_validation": True,
                "command_validation": True,
                "jwt_validation": True,
                "email_validation": True,
                "lfi_prevention": True
            },
            "max_file_size": 10 * 1024 * 1024,
        }
        self.csp_directives = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'", "data:"],
            "font-src": ["'self'"],
            "connect-src": ["'self'"],
            "frame-src": ["'none'"],
            "object-src": ["'none'"],
            "form-action": ["'self'"],
            "base-uri": ["'self'"],
            "frame-ancestors": ["'none'"],
            "upgrade-insecure-requests": []
        }
        self.db_connections = {}
        self._setup_security_logging()

    def _setup_security_logging(self):
        self.security_logger = logging.getLogger('security_events')
        handler = logging.FileHandler('security_events.log')
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.security_logger.addHandler(handler)
        self.security_logger.setLevel(logging.INFO)

    def log_security_event(self, event_type: str, details: Dict[str, Any], severity: str = "info"):
        if not self.log_attacks:
            return
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "severity": severity,
            "details": details
        }
        log_method = getattr(self.security_logger, severity.lower(), self.security_logger.info)
        log_method(f"{event_type}: {json.dumps(details)}")
        self.attack_history.append(log_entry)
        if severity in ["warning", "error", "critical"]:
            self.attack_count += 1

    def sanitize_input(self, value: Union[str, Any], level: str = None) -> str:
        if level is None:
            level = self.config["sanitize_level"]
        try:
            if not isinstance(value, str):
                value = str(value)
            value = html.escape(value)
            value = value.replace('\0', '')
            if level in ["high", "medium"]:
                value = value.replace('\\', '')
                value = value.replace("'", "''")
                value = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', value)
                value = re.sub(r'<!--.*?-->', '', value, flags=re.DOTALL)
                value = re.sub(r'<!\[CDATA\[.*?\]\]>', '', value, flags=re.DOTALL)
            if level == "high":
                value = re.sub(r'[^\w\s\-\.,@]', '', value)
                value = re.sub(r'<script.*?>.*?</script>', '', value, flags=re.DOTALL | re.IGNORECASE)
                dangerous_tags = ['iframe', 'object', 'embed', 'applet', 'form', 'input', 'button']
                for tag in dangerous_tags:
                    value = re.sub(f'<{tag}.*?>.*?</{tag}>', '', value, flags=re.DOTALL | re.IGNORECASE)
                    value = re.sub(f'<{tag}.*?>', '', value, flags=re.DOTALL | re.IGNORECASE)
            logger.info(f"Successfully sanitized input: {value[:100]}")
            self.log_security_event("sanitization_success", {"value": value[:100]}, "info")
            return value
        except Exception as e:
            logger.error(f"Enhanced sanitization error: {e}", exc_info=True)
            self.log_security_event("sanitization_failure", {"error": str(e), "value": str(value)[:100]}, "error")
            raise InjectionError(f"Failed to sanitize input: {str(e)}")

    def validate_sql(self, query: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["sql_validation"]:
                return True
            if not query:
                return False
            dangerous = ["--", ";", "DROP", "DELETE", "UPDATE", "INSERT"]
            for token in dangerous:
                if re.search(r'\b' + re.escape(token) + r'\b', query, re.IGNORECASE):
                    self.log_security_event("sql_injection_detected", {"query": query, "pattern": token}, "warning")
                    return False
            for pattern in self.patterns['sql']:
                if re.search(pattern, query):
                    logger.warning(f"Advanced SQL injection pattern detected: {pattern}")
                    self.log_security_event("advanced_sql_injection", {"query": query, "pattern": pattern}, "warning")
                    return False
            logger.info("SQL validation passed.")
            self.log_security_event("sql_validation_success", {"query": query[:100]}, "info")
            return True
        except Exception as e:
            logger.error(f"SQL validation failed: {e}", exc_info=True)
            self.log_security_event("sql_validation_error", {"query": query, "error": str(e)}, "error")
            return False

    def validate_xss(self, value: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["xss_validation"]:
                return True
            for pattern in self.patterns['xss']:
                if re.search(pattern, value, re.IGNORECASE):
                    logger.warning(f"XSS pattern detected: {pattern}")
                    self.log_security_event("xss_detected", {"value": value[:100], "pattern": pattern}, "warning")
                    return False
            if re.search(r"(?i)<script.*?>.*?</script>", value):
                logger.warning("Advanced XSS pattern detected: <script>...</script>")
                self.log_security_event("advanced_xss_detected", {"value": value[:100]}, "warning")
                return False
            if re.search(r"(?i)data:text/html", value):
                logger.warning("Data URI XSS attack detected")
                self.log_security_event("data_uri_xss", {"value": value[:100]}, "warning")
                return False
            event_handlers = ['onload', 'onerror', 'onmouseover', 'onclick', 'onmouseout', 'onkeypress']
            for handler in event_handlers:
                if re.search(fr"(?i){handler}\s*=", value):
                    logger.warning(f"Event handler XSS detected: {handler}")
                    self.log_security_event("event_handler_xss", {"value": value[:100], "handler": handler}, "warning")
                    return False
            logger.info("XSS validation passed.")
            self.log_security_event("xss_validation_success", {"value": value[:100]}, "info")
            return True
        except Exception as e:
            logger.error(f"XSS validation error: {e}", exc_info=True)
            self.log_security_event("xss_validation_error", {"value": value[:100], "error": str(e)}, "error")
            return False

    def safe_db_query(self, query: str, params: tuple = (), connection_name: str = "default") -> List[Any]:
        try:
            start_time = time.time()
            if not self.validate_sql(query):
                raise InjectionError("SQL injection detected. Query validation failed.")
            if connection_name not in self.db_connections:
                self.db_connections[connection_name] = sqlite3.connect(self.db_path)
            conn = self.db_connections[connection_name]
            cursor = conn.cursor()
            cursor.execute(query, params)
            results = cursor.fetchall()
            execution_time = time.time() - start_time
            if execution_time > 1.0:
                logger.warning(f"Slow query detected: {query[:100]} ({execution_time:.2f}s)")
            return results
        except sqlite3.Error as e:
            error_msg = str(e)
            logger.error(f"Database query error: {error_msg}", exc_info=True)
            self.log_security_event("database_error", {"query": query, "params": str(params), "error": error_msg}, "error")
            raise InjectionError(f"Query failed: {error_msg}")
        except Exception as e:
            logger.error(f"Unexpected error in database query: {e}", exc_info=True)
            self.log_security_event("unexpected_db_error", {"query": query, "error": str(e)}, "critical")
            raise InjectionError(f"Unexpected error during query: {str(e)}")

    def execute_parameterized_query(self, query_template: str, params: Dict[str, Any] = None) -> List[Any]:
        try:
            if params is None:
                params = {}
            if not self.validate_sql(query_template):
                raise InjectionError("SQL injection detected in query template")
            for key, value in params.items():
                if isinstance(value, str) and not self.validate_sql(value):
                    raise InjectionError(f"SQL injection detected in parameter: {key}")
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query_template, params)
                result = [dict(row) for row in cursor.fetchall()]
                return result
        except Exception as e:
            logger.error(f"Parameterized query error: {e}", exc_info=True)
            self.log_security_event("parameterized_query_error", 
                                    {"query": query_template, "params": str(params), "error": str(e)}, 
                                    "error")
            raise InjectionError(f"Parameterized query failed: {str(e)}")

    def encode_payload(self, payload: str) -> str:
        try:
            payload = self.sanitize_input(payload)
            payload = re.sub(r'[^a-zA-Z0-9_\-.]', '', payload)
            return payload
        except Exception as e:
            logger.error(f"Payload encoding error: {e}", exc_info=True)
            self.log_security_event("payload_encoding_failure", {"payload": payload[:100], "error": str(e)}, "error")
            raise InjectionError(f"Failed to encode payload: {str(e)}")

    def check_rate_limit(self, key: str, max_requests: int, time_window: float) -> bool:
        current_time = time.time()
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        self.rate_limits[key] = [
            t for t in self.rate_limits[key]
            if current_time - t <= time_window
        ]
        if len(self.rate_limits[key]) >= max_requests:
            return False
        self.rate_limits[key].append(current_time)
        return True

    def validate_csrf_token(self, token: str, session_token: str) -> bool:
        try:
            return bool(token and session_token and token == session_token)
        except Exception as e:
            logger.error(f"CSRF validation error: {e}", exc_info=True)
            return False

    def validate_json_input(self, json_str: str) -> bool:
        try:
            parsed = json.loads(json_str)
            safe_str = json.dumps(parsed)
            for pattern in self.patterns['nosql'] + self.patterns['template']:
                if re.search(pattern, safe_str):
                    logger.warning(f"Suspicious JSON pattern detected: {pattern}")
                    return False
            if re.search(r"(?i)\$.*\{.*\}", json_str):
                logger.warning("Advanced JSON injection pattern detected: ${...}")
                return False
            return True
        except json.JSONDecodeError:
            return False
        except Exception as e:
            logger.error(f"JSON validation error: {e}", exc_info=True)
            return False

    def add_injection(self, injection_id: str, injection_data: Any) -> bool:
        try:
            self._injections[injection_id] = injection_data
            logger.info(f"Added injection with ID {injection_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add injection {injection_id}: {e}", exc_info=True)
            return False

    def remove_injection(self, injection_id: str) -> bool:
        try:
            if injection_id in self._injections:
                del self._injections[injection_id]
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove injection {injection_id}: {e}", exc_info=True)
            return False

    async def validate_injection(self, technique: str, data: Any) -> bool:
        if not technique or not data:
            return False
        try:
            if technique == 'manifest':
                return self.validate_command(str(data))
            elif hasattr(self.security_validator, f"validate_{technique}"):
                validator_method = getattr(self.security_validator, f"validate_{technique}")
                if asyncio.iscoroutinefunction(validator_method):
                    return await validator_method(str(data))
                return validator_method(str(data))
            else:
                return self.validate_command(str(data))
        except Exception as e:
            logger.error(f"{technique} validation failed: {e}")
            return False

    def validate_xml(self, xml_data: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["xml_validation"]:
                return True
            for pattern in self.patterns['xml']:
                if re.search(pattern, xml_data, re.IGNORECASE):
                    logger.warning(f"XML injection pattern detected: {pattern}")
                    self.log_security_event("xml_injection_detected", {"xml_data": xml_data[:100], "pattern": pattern}, "warning")
                    return False
            logger.info("XML validation passed.")
            self.log_security_event("xml_validation_success", {"xml_data": xml_data[:100]}, "info")
            return True
        except Exception as e:
            logger.error(f"XML validation error: {e}", exc_info=True)
            self.log_security_event("xml_validation_error", {"xml_data": xml_data[:100], "error": str(e)}, "error")
            return False

    def validate_ldap(self, ldap_query: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["ldap_validation"]:
                return True
            for pattern in self.patterns['ldap']:
                if re.search(pattern, ldap_query, re.IGNORECASE):
                    logger.warning(f"LDAP injection pattern detected: {pattern}")
                    self.log_security_event("ldap_injection_detected", {"ldap_query": ldap_query[:100], "pattern": pattern}, "warning")
                    return False
            logger.info("LDAP validation passed.")
            self.log_security_event("ldap_validation_success", {"ldap_query": ldap_query[:100]}, "info")
            return True
        except Exception as e:
            logger.error(f"LDAP validation error: {e}", exc_info=True)
            self.log_security_event("ldap_validation_error", {"ldap_query": ldap_query[:100], "error": str(e)}, "error")
            return False

    def validate_command(self, command: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["command_validation"]:
                return True
            for pattern in self.patterns['command']:
                if re.search(pattern, command, re.IGNORECASE):
                    logger.warning(f"Command injection pattern detected: {pattern}")
                    self.log_security_event("command_injection_detected", {"command": command[:100], "pattern": pattern}, "warning")
                    return False
            logger.info("Command validation passed.")
            self.log_security_event("command_validation_success", {"command": command[:100]}, "info")
            return True
        except Exception as e:
            logger.error(f"Command validation error: {e}", exc_info=True)
            self.log_security_event("command_validation_error", {"command": command[:100], "error": str(e)}, "error")
            return False
            
    def check_file_inclusion(self, file_path: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["file_inclusion_check"]:
                return True
            for pattern in self.patterns['file']:
                if re.search(pattern, file_path, re.IGNORECASE):
                    logger.warning(f"File inclusion pattern detected: {pattern}")
                    self.log_security_event("file_inclusion_detected", {"file_path": file_path[:100], "pattern": pattern}, "warning")
                    return False
            logger.info("File inclusion check passed.")
            self.log_security_event("file_inclusion_success", {"file_path": file_path[:100]}, "info")
            return True
        except Exception as e:
            logger.error(f"File inclusion check error: {e}", exc_info=True)
            self.log_security_event("file_inclusion_error", {"file_path": file_path[:100], "error": str(e)}, "error")
            return False

    def check_ip_rate_limit(self, ip_address: str, key: str, max_requests: int, time_window: float) -> bool:
        current_time = time.time()
        if ip_address not in self.ip_rate_limits:
            self.ip_rate_limits[ip_address] = {}
        if key not in self.ip_rate_limits[ip_address]:
            self.ip_rate_limits[ip_address][key] = []
        self.ip_rate_limits[ip_address][key] = [
            t for t in self.ip_rate_limits[ip_address][key]
            if current_time - t <= time_window
        ]
        if len(self.ip_rate_limits[ip_address][key]) >= max_requests:
            return False
        self.ip_rate_limits[ip_address][key].append(current_time)
        return True

    def generate_csrf_token(self) -> str:
        return secrets.token_hex(32)

    def validate_redirect(self, url: str) -> bool:
        try:
            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                return True
            if parsed_url.netloc in self.config["trusted_domains"]:
                return True
            logger.warning(f"Untrusted redirect detected: {url}")
            self.log_security_event("untrusted_redirect_detected", {"url": url}, "warning")
            return False
        except Exception as e:
            logger.error(f"Redirect validation error: {e}", exc_info=True)
            self.log_security_event("redirect_validation_error", {"url": url, "error": str(e)}, "error")
            return False
            
    def validate_jwt(self, token: str, secret: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["jwt_validation"]:
                return True
            jwt.decode(token, secret, algorithms=["HS256"])
            logger.info("JWT validation passed.")
            self.log_security_event("jwt_validation_success", {"token": token[:100]}, "info")
            return True
        except jwt.ExpiredSignatureError:
            logger.warning("JWT signature expired.")
            self.log_security_event("jwt_expired", {"token": token[:100]}, "warning")
            return False
        except jwt.InvalidSignatureError:
            logger.warning("JWT signature is invalid.")
            self.log_security_event("jwt_invalid_signature", {"token": token[:100]}, "warning")
            return False
        except jwt.InvalidTokenError as e:
            logger.error(f"JWT validation error: {e}", exc_info=True)
            self.log_security_event("jwt_validation_error", {"token": token[:100], "error": str(e)}, "error")
            return False

    def detect_command_injection_in_file(self, file_content: bytes) -> bool:
        try:
            content = file_content.decode('utf-8', errors='ignore')
            for pattern in self.patterns['shell']:
                if re.search(pattern, content, re.IGNORECASE):
                    logger.warning(f"Command injection pattern detected in file content: {pattern}")
                    self.log_security_event("command_injection_in_file_detected", {"pattern": pattern}, "warning")
                    return True
            return False
        except Exception as e:
            logger.error(f"Error detecting command injection in file: {e}", exc_info=True)
            return True

    def validate_email(self, email: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["email_validation"]:
                return True
            validated_email = validate_email(email)
            email = validated_email.email
            logger.info("Email validation passed.")
            self.log_security_event("email_validation_success", {"email": email}, "info")
            return True
        except EmailNotValidError as e:
            logger.warning(f"Invalid email address: {e}")
            self.log_security_event("invalid_email", {"email": email, "error": str(e)}, "warning")
            return False

    def sanitize_html(self, html_content: str) -> str:
        try:
            html_content = re.sub(r'<(script|iframe|object|embed|applet|meta|style).*?>.*?</\1>', '', html_content, flags=re.IGNORECASE | re.DOTALL)
            html_content = re.sub(r'javascript:.*?', '', html_content, flags=re.IGNORECASE)
            html_content = re.sub(r'on\w+\s*=', '', html_content, flags=re.IGNORECASE)
            logger.info("HTML sanitization passed.")
            self.log_security_event("html_sanitization_success", {"html_content": html_content[:100]}, "info")
            return html_content
        except Exception as e:
            logger.error(f"HTML sanitization error: {e}", exc_info=True)
            self.log_security_event("html_sanitization_error", {"html_content": html_content[:100], "error": str(e)}, "error")
            return ""

    def prevent_lfi(self, file_path: str, base_dir: str) -> bool:
        try:
            if not self.config["enable_security_checks"]["lfi_prevention"]:
                return True
            abs_path = os.path.abspath(file_path)
            base_path = os.path.abspath(base_dir)
            if not abs_path.startswith(base_path):
                logger.warning(f"LFI attack detected: {file_path}")
                self.log_security_event("lfi_attack_detected", {"file_path": file_path}, "warning")
                return False
            logger.info("LFI prevention check passed.")
            self.log_security_event("lfi_prevention_success", {"file_path": file_path}, "info")
            return True
        except Exception as e:
            logger.error(f"LFI prevention error: {e}", exc_info=True)
            self.log_security_event("lfi_prevention_error", {"file_path": file_path, "error": str(e)}, "error")
            return False
