

from __future__ import annotations
import argparse
import json
import os
import shutil
import tempfile
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from dotenv import load_dotenv
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeRemainingColumn
)
from rich.prompt import Prompt

import asyncio

from utils import setup_logger, run_shell_command, console, SecurityValidator, SecurityError

load_dotenv()

logger = setup_logger('apk_signer', 'apk_signer.log')


class SigningScheme(Enum):
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"
    V4 = "v4"


class SigningMethod(Enum):
    APKSIGNER = "apksigner"
    JARSIGNER = "jarsigner"
    UBER = "uber"


class APKSignerError(SecurityError):
    pass


class APKSecurityError(APKSignerError):
    pass


@dataclass
class APKInfo:
    package_name: str
    version_code: str
    version_name: str
    min_sdk: int
    target_sdk: int
    app_name: str
    permissions: List[str]
    file_size: int
    libraries: List[str] = field(default_factory=list)
    activities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    receivers: List[str] = field(default_factory=list)
    content_providers: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    signature_schemes: List[str] = field(default_factory=list)


@dataclass
class SigningResult:
    success: bool
    output_path: Optional[Path] = None
    message: str = ""
    verification_passed: bool = False
    verification_details: Dict[str, Any] = field(default_factory=dict)


class APKSignerConfig:
    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config_path = Path(config_path) if config_path else Path.home() / ".apksigner" / "config.json"
        self.settings: Dict[str, Any] = self._load_config()
        if "keystore_history" not in self.settings:
            self.settings["keystore_history"] = []
        if "signing_schemes" not in self.settings:
            self.settings["signing_schemes"] = {"v1": True, "v2": True, "v3": True, "v4": False}

    def _load_config(self) -> Dict[str, Any]:
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                logger.debug(f"Configuration loaded from {self.config_path}")
                return settings
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from config file: {e}")
                return {}
        else:
            logger.info(f"No configuration file found at {self.config_path}. Using defaults.")
            return {}

    def save_config(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4)
            logger.debug(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        return self.settings.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self.settings[key] = value
        self.save_config()

    def add_keystore_to_history(self, keystore_path: str) -> None:
        keystore_history = self.settings.get("keystore_history", [])
        if (keystore_path in keystore_history):
            keystore_history.remove(keystore_path)
        keystore_history.insert(0, keystore_path)
        self.settings["keystore_history"] = keystore_history[:10]
        self.save_config()

    def get_signing_schemes(self) -> Dict[str, bool]:
        return self.settings.get("signing_schemes", {"v1": True, "v2": True, "v3": True, "v4": False})

    def set_signing_scheme(self, scheme: Union[str, SigningScheme], enabled: bool) -> None:
        if isinstance(scheme, SigningScheme):
            scheme_name = scheme.value
        else:
            scheme_name = scheme
        if "signing_schemes" not in self.settings:
            self.settings["signing_schemes"] = {}
        self.settings["signing_schemes"][scheme_name] = enabled
        self.save_config()


class APKSigner:
    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.ANSWER_PHONE_CALLS",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.RECEIVE_MMS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.ACCESS_MEDIA_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.WRITE_SETTINGS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    }

    def __init__(
        self,
        apk_path: str,
        keystore_path: str,
        keystore_password: str,
        key_alias: str,
        key_password: str,
        config: Optional[APKSignerConfig] = None
    ) -> None:
        self.apk_path: Path = Path(apk_path)
        self.keystore_path: Path = Path(keystore_path)
        self.keystore_password: str = keystore_password
        self.key_alias: str = key_alias
        self.key_password: str = key_password
        self.config = config or APKSignerConfig()
        self.run_command = lambda cmd: run_shell_command(cmd, logger)
        self.security_validator = SecurityValidator()
        self.signing_progress: Dict[Path, str] = {}
        self.signature_verifications = defaultdict(list)
        self.proguard_enabled: bool = False
        self.r8_enabled: bool = False
        self.proguard_rules: List[str] = []
        self.analysis_results: Dict[str, Any] = {}
        self.temp_dir = Path(tempfile.mkdtemp(prefix="apksigner_"))
        if self.config and Path(keystore_path).exists():
            self.config.add_keystore_to_history(str(keystore_path))

    def __del__(self) -> None:
        try:
            if hasattr(self, 'temp_dir') and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            logger.error(f"Error cleaning up temporary directory: {e}")

    async def optimize_with_proguard(self, input_apk: Path) -> Optional[Path]:
        try:
            if not self.proguard_enabled:
                return input_apk
            from payload_manager import PayloadManager
            manager = PayloadManager(str(input_apk), "")
            manager.r8_enabled = self.r8_enabled
            manager.proguard_rules = self.proguard_rules
            optimized_apk = await manager.optimize_with_proguard(str(input_apk))
            if optimized_apk:
                return Path(optimized_apk)
            return input_apk
        except Exception as e:
            logger.error(f"ProGuard optimization failed: {e}")
            return input_apk

    async def _validate_apk_integrity(self) -> None:
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
                required_files = ['AndroidManifest.xml', 'classes.dex']
                found_files = zip_ref.namelist()
                for required in required_files:
                    if not any(f.endswith(required) for f in found_files):
                        raise APKSignerError(f"Invalid APK: {required} not found in APK")
            if self.apk_path.stat().st_size < 10000:
                raise APKSignerError(f"APK file is suspiciously small: {self.apk_path.stat().st_size} bytes")
            logger.info("APK integrity validated successfully")
        except zipfile.BadZipFile:
            raise APKSignerError(f"File is not a valid ZIP/APK file: {self.apk_path}")
        except Exception as e:
            logger.error(f"APK integrity validation failed: {e}")
            raise APKSignerError(f"APK integrity validation failed: {e}")

    async def _validate_keystore(self) -> None:
        if not self.keystore_path.exists():
            raise APKSignerError(f"Keystore file not found: {self.keystore_path}")
        try:
            command = (
                f"keytool -list -keystore \"{self.keystore_path}\" "
                f"-storepass {self.keystore_password}"
            )
            output = self.run_command(command)
            if self.key_alias not in output:
                raise APKSignerError(f"Key alias '{self.key_alias}' not found in keystore")
            logger.info(f"Keystore validated successfully, found key alias: {self.key_alias}")
        except Exception as e:
            logger.error(f"Keystore validation failed: {e}")
            raise APKSignerError(f"Keystore validation failed: {e}")

    async def validate_command(self, command: str) -> bool:
        return await self.security_validator.validate_command(command)

    async def _sign_with_method(self, method: str) -> bool:
        method = method.lower()
        output_apk = self.apk_path.parent / f"signed_{self.apk_path.name}"
        if method == 'apksigner':
            return self.sign_with_apksigner(output_apk)
        elif method == 'jarsigner':
            return self.sign_with_jarsigner(output_apk)
        elif method == 'uber':
            return self.sign_with_uber_apk_signer(output_apk)
        else:
            logger.error(f"Unknown signing method: {method}")
            console.print(f"[red]Unknown signing method: {method}[/red]")
            return False

    async def _verify_signature_comprehensive(self) -> bool:
        try:
            if not self.verify_apksigner(self.apk_path):
                raise APKSignerError("apksigner verification failed")
            if not self.verify_jarsigner(self.apk_path):
                raise APKSignerError("jarsigner verification failed")
            logger.info("Comprehensive signature verification passed")
            return True
        except Exception as e:
            logger.error(f"Comprehensive signature verification failed: {e}")
            raise

    def check_tool_availability(self, tool_name: str) -> bool:
        tool_path = shutil.which(tool_name)
        if (tool_path):
            logger.info(f"{tool_name} found at {tool_path}.")
            return True
        else:
            logger.error(f"{tool_name} not found. Please install it and ensure it's in the PATH.")
            console.print(f"[red]{tool_name} not found. Please install it and ensure it's in the PATH.[/red]")
            return False

    def sign_with_apksigner(self, output_apk_path: Path) -> bool:
        if not self.check_tool_availability("apksigner"):
            return False
        schemes = self.config.get_signing_schemes()
        command = (
            f"apksigner sign "
            f"--v1-signing-enabled {'true' if schemes.get('v1', True) else 'false'} "
            f"--v2-signing-enabled {'true' if schemes.get('v2', True) else 'false'} "
            f"--v3-signing-enabled {'true' if schemes.get('v3', True) else 'false'} "
            f"--v4-signing-enabled {'true' if schemes.get('v4', False) else 'false'} "
        )
        if schemes.get('v3', True):
            command += "--rotation-min-sdk-version 28 "
        command += (
            f"--ks \"{self.keystore_path}\" "
            f"--ks-pass pass:{self.keystore_password} "
            f"--ks-key-alias {self.key_alias} "
            f"--key-pass pass:{self.key_password} "
            f"--out \"{output_apk_path}\" \"{self.apk_path}\""
        )
        try:
            self.run_command(command)
            logger.info("APK signed successfully with enhanced signing schemes (apksigner).")
            return True
        except APKSignerError as e:
            logger.error(f"Enhanced signing failed: {e}")
            return False

    def sign_with_jarsigner(self, output_apk_path: Path) -> bool:
        if not self.check_tool_availability("jarsigner"):
            return False
        unsigned_apk = self.temp_dir / f"unsigned_{self.apk_path.name}"
        try:
            shutil.copy(self.apk_path, unsigned_apk)
            logger.info(f"Copied APK to {unsigned_apk} for signing.")
            command = (
                f"jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 "
                f"-keystore \"{self.keystore_path}\" "
                f"-storepass {self.keystore_password} "
                f"-keypass {self.key_password} "
                f"\"{unsigned_apk}\" {self.key_alias}"
            )
            self.run_command(command)
            logger.info("APK signed successfully with jarsigner.")
            console.print("[green]APK signed successfully with jarsigner.[/green]")
            shutil.move(str(unsigned_apk), str(output_apk_path))
            logger.info(f"Signed APK moved to {output_apk_path}.")
            return True
        except APKSignerError as e:
            console.print(f"[red]jarsigner error: {e}[/red]")
            return False
        except Exception as e:
            logger.exception(f"Exception during jarsigner signing: {e}")
            console.print(f"[red]Exception during jarsigner signing: {e}[/red]")
            return False

    def sign_with_uber_apk_signer(self, output_apk_path: Path) -> bool:
        if not self.check_tool_availability("uber-apk-signer"):
            return False
        schemes = self.config.get_signing_schemes()
        command = (
            f"uber-apk-signer --apks \"{self.apk_path}\" "
            f"--allowResign "
            f"--overwrite "
            f"--ks \"{self.keystore_path}\" "
            f"--ksPass {self.keystore_password} "
            f"--ksKeyAlias {self.key_alias} "
            f"--ksKeyPass {self.key_password} "
        )
        if not schemes.get('v1', True):
            command += "--skipSigningSchemeV1 "
        if not schemes.get('v2', True):
            command += "--skipSigningSchemeV2 "
        if not schemes.get('v3', True):
            command += "--skipSigningSchemeV3 "
        if schemes.get('v4', False):
            command += "--enableSigningSchemeV4 "
        try:
            self.run_command(command)
            signed_file = self.apk_path.parent / f"{self.apk_path.stem}-aligned-signed.apk"
            if signed_file.exists():
                shutil.move(str(signed_file), str(output_apk_path))
            logger.info("APK signed successfully with uber-apk-signer.")
            console.print("[green]APK signed successfully with uber-apk-signer.[/green]")
            return True
        except APKSignerError as e:
            logger.error(f"uber-apk-signer failed: {e}")
            console.print(f"[red]uber-apk-signer error: {e}[/red]")
            return False

    def verify_apksigner(self, apk_path: Path) -> bool:
        if not self.check_tool_availability("apksigner"):
            return False
        command = f"apksigner verify --verbose \"{apk_path}\""
        try:
            self.run_command(command)
            logger.info("APK verified successfully with apksigner.")
            console.print("[green]APK verified successfully with apksigner.[/green]")
            return True
        except APKSignerError as e:
            console.print(f"[red]apksigner verify error: {e}[/red]")
            return False

    def verify_jarsigner(self, apk_path: Path) -> bool:
        if not self.check_tool_availability("jarsigner"):
            return False
        command = f"jarsigner -verify -verbose -certs \"{apk_path}\""
        try:
            output = self.run_command(command)
            if "jar verified" in output.lower():
                logger.info("APK verified successfully with jarsigner.")
                console.print("[green]APK verified successfully with jarsigner.[/green]")
                return True
            else:
                logger.error(f"jarsigner verify error: {output}")
                console.print(f"[red]jarsigner verify error: {output}[/red]")
                return False
        except APKSignerError as e:
            console.print(f"[red]jarsigner verify error: {e}[/red]")
            return False

    def verify_signature_details(self, apk_path: Path) -> Dict[str, Any]:
        if not self.check_tool_availability("apksigner"):
            return {}
        command = f"apksigner verify --verbose --print-certs \"{apk_path}\""
        try:
            output = self.run_command(command)
            verification_details = {
                'v1_scheme': 'v1 scheme: true' in output,
                'v2_scheme': 'v2 scheme: true' in output,
                'v3_scheme': 'v3 scheme: true' in output,
                'v4_scheme': 'v4 scheme: true' in output,
                'cert_info': self._parse_cert_info(output)
            }
            logger.info(f"Signature verification details: {verification_details}")
            return verification_details
        except APKSignerError as e:
            logger.error(f"Verification failed: {e}")
            return {}

    def _parse_cert_info(self, output: str) -> Dict[str, str]:
        cert_info: Dict[str, str] = {}
        cert_lines = [line for line in output.split('\n') if 'Certificate' in line]
        for line in cert_lines:
            if 'Subject:' in line:
                cert_info['subject'] = line.split('Subject:', 1)[1].strip()
            elif 'SHA-256:' in line:
                cert_info['sha256'] = line.split('SHA-256:', 1)[1].strip()
        return cert_info

    def sign_apk(self, method: str = 'apksigner', output_apk_path: Optional[str] = None) -> SigningResult:
        method = method.lower()
        output_apk = Path(output_apk_path) if output_apk_path else self.apk_path.parent / f"signed_{self.apk_path.name}"
        result = SigningResult(success=False, output_path=output_apk, message="")
        try:
            asyncio.run(self._validate_apk_integrity())
            asyncio.run(self._validate_keystore())
            if method == 'apksigner':
                result.success = self.sign_with_apksigner(output_apk)
                if result.success:
                    result.message = "APK signed successfully with apksigner"
                else:
                    result.message = "Failed to sign APK with apksigner"
            elif method == 'jarsigner':
                result.success = self.sign_with_jarsigner(output_apk)
                if result.success:
                    result.message = "APK signed successfully with jarsigner"
                else:
                    result.message = "Failed to sign APK with jarsigner"
            elif method == 'uber':
                result.success = self.sign_with_uber_apk_signer(output_apk)
                if result.success:
                    result.message = "APK signed successfully with uber-apk-signer"
                else:
                    result.message = "Failed to sign APK with uber-apk-signer"
            else:
                result.message = f"Unknown signing method: {method}"
                logger.error(result.message)
                return result
            if result.success:
                if method == 'apksigner':
                    result.verification_passed = self.verify_apksigner(output_apk)
                else:
                    result.verification_passed = self.verify_jarsigner(output_apk)
                result.verification_details = self.verify_signature_details(output_apk)
                if result.verification_passed:
                    logger.info(f"{result.message} and verified successfully")
                else:
                    logger.warning(f"{result.message} but verification failed")
                    result.message += " but verification failed"
            return result
        except Exception as e:
            logger.exception(f"Error during APK signing: {e}")
            result.message = f"Error during APK signing: {str(e)}"
            return result

    def align_apk(self, input_apk: Path, output_apk: Path) -> bool:
        if not self.check_tool_availability("zipalign"):
            return False
        command = f"zipalign -v -p 4 \"{input_apk}\" \"{output_apk}\""
        try:
            self.run_command(command)
            logger.info("APK aligned successfully")
            console.print("[green]APK aligned successfully.[/green]")
            return True
        except APKSignerError as e:
            logger.error(f"Zipalign error: {e}")
            console.print(f"[red]Zipalign error: {e}[/red]")
            return False

    def optimize_apk(self, input_apk: Path) -> Path:
        optimized_apk = input_apk.parent / f"optimized_{input_apk.name}"
        try:
            if shutil.which("optimize-apk"):
                command = f"optimize-apk \"{input_apk}\" -o \"{optimized_apk}\""
                self.run_command(command)
                logger.info(f"APK optimized successfully: {optimized_apk}")
                console.print(f"[green]APK optimized successfully: {optimized_apk}[/green]")
                return optimized_apk
            else:
                logger.warning("optimize-apk tool not available. Skipping optimization.")
                return input_apk
        except APKSignerError as e:
            logger.error(f"Optimize APK error: {e}")
            console.print(f"[red]Optimize APK error: {e}[/red]")
            return input_apk

    def get_apk_info(self, apk_path: Path) -> Optional[APKInfo]:
        if not self.check_tool_availability("aapt"):
            return None
        try:
            command = f"aapt dump badging \"{apk_path}\""
            output = self.run_command(command)
            return self._parse_apk_info(output, apk_path)
        except APKSignerError:
            return None

    def _parse_apk_info(self, aapt_output: str, apk_path: Path) -> APKInfo:
        info = {
            'package_name': '',
            'version_code': '',
            'version_name': '',
            'min_sdk': 0,
            'target_sdk': 0,
            'app_name': '',
            'permissions': [],
            'file_size': apk_path.stat().st_size
        }
        for line in aapt_output.split('\n'):
            if line.startswith('package:'):
                parts = line.split(' ')
                for part in parts:
                    if part.startswith("name="):
                        info['package_name'] = part.split('=', 1)[1].strip("'")
                    elif part.startswith("versionCode="):
                        info['version_code'] = part.split('=', 1)[1].strip("'")
                    elif part.startswith("versionName="):
                        info['version_name'] = part.split('=', 1)[1].strip("'")
            elif line.startswith('application-label:'):
                info['app_name'] = line.split(':', 1)[1].strip().strip("'")
            elif line.startswith('uses-permission:'):
                permission = line.split(':', 1)[1].strip().strip("'")
                info['permissions'].append(permission)
            elif "sdkVersion" in line:
                try:
                    info['min_sdk'] = int(line.split('sdkVersion:', 1)[1].strip())
                except ValueError:
                    pass
            elif "targetSdkVersion" in line:
                try:
                    info['target_sdk'] = int(line.split('targetSdkVersion:', 1)[1].strip())
                except ValueError:
                    pass
        apk_info = APKInfo(**info)
        logger.debug(f"APK Info: {apk_info}")
        return apk_info

    def sign_batch_parallel(self, apk_paths: List[str], method: str = 'apksigner', max_workers: int = 4) -> None:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task("[cyan]Signing APKs...", total=len(apk_paths))

            def _process_single_apk(apk_path: str) -> bool:
                try:
                    apk = Path(apk_path)
                    aligned_apk = apk.parent / f"aligned_{apk.name}"
                    if self.align_apk(apk, aligned_apk):
                        optimized_apk = self.optimize_apk(aligned_apk)
                        output_apk = apk.parent / f"signed_{apk.name}"
                        return self.sign_apk(method=method, output_apk_path=str(output_apk))
                    return False
                except Exception as e:
                    logger.exception(f"Error processing {apk_path}: {e}")
                    return False

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_process_single_apk, apk): apk for apk in apk_paths}
                for future in as_completed(futures):
                    progress.advance(task_id)
                    apk = futures[future]
                    try:
                        if not future.result():
                            logger.error(f"Failed to sign {apk}")
                            console.print(f"[red]Failed to sign {apk}[/red]")
                    except Exception as e:
                        logger.exception(f"Error signing {apk}: {e}")
                        console.print(f"[red]Error signing {apk}: {e}[/red]")

    def display_apk_info(self, apk_info: APKInfo) -> None:
        from rich.table import Table
        table = Table(title="APK Information", show_lines=True)
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        table.add_row("Package Name", apk_info.package_name)
        table.add_row("Version Code", apk_info.version_code)
        table.add_row("Version Name", apk_info.version_name)
        table.add_row("Min SDK", str(apk_info.min_sdk))
        table.add_row("Target SDK", str(apk_info.target_sdk))
        table.add_row("App Name", apk_info.app_name)
        table.add_row("Permissions", ", ".join(apk_info.permissions))
        table.add_row("File Size (bytes)", str(apk_info.file_size))
        console.print(table)

    async def verify_apk_signature(self, apk_path: str) -> bool:
        try:
            signed = self.verify_apksigner(Path(apk_path))
            jarsigned = self.verify_jarsigner(Path(apk_path))
            return signed and jarsigned
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False

    def add_proguard_rule(self, rule: str) -> None:
        if not hasattr(self, 'proguard_rules'):
            self.proguard_rules = []
        self.proguard_rules.append(rule)
        logger.info(f"Added ProGuard rule: {rule}")

    async def sign_apk_secure(self) -> bool:
        try:
            validation_tasks = [
                self._validate_apk_integrity(),
                self._validate_keystore()
            ]
            await asyncio.gather(*validation_tasks)
            output_apk = self.apk_path.parent / f"signed_{self.apk_path.name}"
            if self.check_tool_availability("apksigner"):
                signing_success = self.sign_with_apksigner(output_apk)
            elif self.check_tool_availability("jarsigner"):
                logger.warning("apksigner not found, falling back to jarsigner")
                console.print("[yellow]Warning: apksigner not found, falling back to jarsigner[/yellow]")
                signing_success = self.sign_with_jarsigner(output_apk)
            else:
                logger.error("No valid signing tools found. Please install Android SDK Build Tools.")
                console.print("[red]Error: No valid signing tools found. Please install Android SDK Build Tools.[/red]")
                return False
            if not signing_success:
                logger.error("Failed to sign APK")
                console.print("[red]Failed to sign APK[/red]")
                return False
            verification_success = await self._verify_signature_comprehensive()
            if verification_success:
                logger.info(f"APK signed and verified successfully: {output_apk}")
                console.print(f"[green]APK signed and verified successfully: {output_apk}[/green]")
                details = self.verify_signature_details(output_apk)
                for scheme, enabled in {
                    'v1_scheme': details.get('v1_scheme', False),
                    'v2_scheme': details.get('v2_scheme', False),
                    'v3_scheme': details.get('v3_scheme', False),
                    'v4_scheme': details.get('v4_scheme', False)
                }.items():
                    status = "[green]enabled[/green]" if enabled else "[yellow]disabled[/yellow]"
                    console.print(f"  {scheme}: {status}")
                if 'cert_info' in details and details['cert_info']:
                    console.print("\n[bold]Certificate Information:[/bold]")
                    for key, value in details['cert_info'].items():
                        console.print(f"  {key}: {value}")
                return True
            else:
                logger.error("APK signed but failed verification")
                console.print("[red]APK signed but failed verification[/red]")
                return False
        except APKSignerError as e:
            logger.error(f"Secure signing process failed: {e}")
            console.print(f"[red]Signing error: {e}[/red]")
            return False
        except Exception as e:
            logger.exception(f"Unexpected error during secure signing: {e}")
            console.print(f"[red]Unexpected error: {e}[/red]")
            return False


def get_credentials(config: APKSignerConfig) -> Tuple[str, str, str]:
    keystore_password = os.getenv("KEYSTORE_PASSWORD") or config.get("keystore_password")
    key_alias = os.getenv("KEY_ALIAS") or config.get("key_alias")
    key_password = os.getenv("KEY_PASSWORD") or config.get("key_password")
    if not keystore_password:
        keystore_password = getpass("Enter keystore password: ").strip()
    if not key_alias:
        key_alias = Prompt.ask("Enter the key alias")
    if not key_password:
        key_password = getpass("Enter key password: ").strip()
    return keystore_password, key_alias, key_password

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="APK Signer Tool")
    parser.add_argument("-a", "--apk", help="Path to the APK file")
    parser.add_argument("-k", "--keystore", help="Path to the keystore file")
    parser.add_argument("-o", "--output", help="Name for the signed APK")
    parser.add_argument("-m", "--method", choices=['apksigner', 'jarsigner', 'uber'], help="Signing method")
    parser.add_argument("--batch", nargs='*', help="Sign multiple APKs. Provide a list of paths.")
    parser.add_argument("--parallel", type=int, default=4, help="Number of parallel processes")
    parser.add_argument("--optimize", action="store_true", help="Optimize APK before signing")
    parser.add_argument("--info", action="store_true", help="Display APK information")
    parser.add_argument("--config", help="Path to configuration file.")
    return parser.parse_args()

def main() -> None:
    args = parse_arguments()
    config = APKSignerConfig(config_path=args.config)
    if args.batch:
        keystore_path = args.keystore or config.get("keystore_path")
        if not keystore_path:
            console.print("[red]Keystore path must be provided.[/red]")
            return
        keystore_password, key_alias, key_password = get_credentials(config)
        signer = APKSigner(
            apk_path="",
            keystore_path=keystore_path,
            keystore_password=keystore_password,
            key_alias=key_alias,
            key_password=key_password,
            config=config
        )
        signer.sign_batch_parallel(args.batch, method=args.method or 'apksigner', max_workers=args.parallel)
        return
    if not args.apk or not args.keystore:
        console.print("[red]Error: --apk and --keystore are required.[/red]")
        return
    apk_path = args.apk
    keystore_path = args.keystore
    output_apk = args.output
    method = args.method or 'apksigner'
    if not Path(apk_path).exists():
        console.print(f"[red]Error: APK file does not exist: {apk_path}[/red]")
        logger.error(f"APK file does not exist: {apk_path}")
        return
    if not Path(keystore_path).exists():
        console.print(f"[red]Error: Keystore file does not exist: {keystore_path}[/red]")
        logger.error(f"Keystore file does not exist: {keystore_path}")
        return
    keystore_password, key_alias, key_password = get_credentials(config)
    config.set("keystore_path", keystore_path)
    config.set("key_alias", key_alias)
    signer = APKSigner(
        apk_path=apk_path,
        keystore_path=keystore_path,
        keystore_password=keystore_password,
        key_alias=key_alias,
        key_password=key_password,
        config=config
    )
    if args.info:
        apk_info = signer.get_apk_info(Path(apk_path))
        if apk_info:
            signer.display_apk_info(apk_info)
        else:
            console.print("[red]Failed to retrieve APK information.[/red]")
        return
    if args.optimize:
        aligned_apk = Path(apk_path).parent / f"aligned_{Path(apk_path).name}"
        if signer.align_apk(Path(apk_path), aligned_apk):
            apk_to_sign = signer.optimize_apk(aligned_apk)
        else:
            apk_to_sign = Path(apk_path)
    else:
        apk_to_sign = Path(apk_path)
    signer.apk_path = apk_to_sign
    success = signer.sign_apk(method=method, output_apk_path=output_apk)
    if success:
        signed_apk = Path(output_apk) if output_apk else Path(apk_path).parent / f"signed_{Path(apk_path).name}"
        console.print(f"[green]APK signed successfully: {signed_apk}[/green]")
        logger.info(f"APK signed successfully: {signed_apk}")
        console.print(f"\n[bold yellow]Verifying the signed APK...[/bold yellow]")
        verify_success = (signer.verify_apksigner(signed_apk) if method == 'apksigner'
                          else signer.verify_jarsigner(signed_apk))
        if verify_success:
            console.print(f"[green]APK verified successfully: {signed_apk}[/green]")
            logger.info(f"APK verified successfully: {signed_apk}")
        else:
            console.print(f"[red]APK verification failed: {signed_apk}[/red]")
            logger.error(f"APK verification failed: {signed_apk}")
    else:
        console.print("[red]APK signing failed.[/red]")
        logger.error("APK signing failed.")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logger.exception(f"Unhandled exception: {exc}")
        console.print(f"[red]An unexpected error occurred: {exc}[/red]")
