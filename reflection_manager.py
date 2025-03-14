import types
import asyncio
import marshal
import dill
import time
import hashlib
import ast
from typing import Any, Dict, Optional, Callable, Tuple, Set, get_type_hints

from utils import setup_logger, SecurityValidator, SecurityError, async_run_shell_command

logger = setup_logger('reflection_manager', 'reflection_manager.log')


class ReflectionError(SecurityError):
    pass


class ReflectionManager:
    def __init__(self, cache_ttl: int = 3600):
        self.security = SecurityValidator()
        self.loaded_modules: Dict[str, Tuple[types.ModuleType, float]] = {}
        self.dynamic_classes: Dict[str, Tuple[type, float]] = {}
        self.method_cache: Dict[str, Tuple[Callable, float]] = {}
        self.bytecode_cache: Dict[str, Tuple[Any, float]] = {}
        
        self.max_cache_size = 100
        self.cache_ttl = cache_ttl
        self._code_signatures: Dict[str, str] = {}
        
        self.safety_checks = {
            'blacklist': [
                'os.system',
                'subprocess.',
                'eval',
                'exec'
            ],
            'max_complexity': 10
        }

        self.container: Dict[str, Any] = {}
        self.lazy_modules: Dict[str, Callable] = {}
        self.tracked_dependencies: Dict[str, Set[str]] = {}

    def _verify_signature(self, code: str, signature: str) -> bool:
        computed = hashlib.sha256(code.encode()).hexdigest()
        return computed == signature

    def _is_cache_valid(self, timestamp: float) -> bool:
        return (time.time() - timestamp) < self.cache_ttl

    async def load_class(self, class_name: str, code: str, signature: Optional[str] = None) -> Optional[type]:
        try:
            if signature and not self._verify_signature(code, signature):
                raise ReflectionError("Invalid code signature.")

            await self._check_code_safety(code)

            code = code.strip()
            if not code or len(code) > 1_000_000:
                raise ReflectionError("Invalid code size.")
                
            if not await self.security.validate_command(code):
                raise ReflectionError("Security validation failed for the provided code.")
                
            import builtins
            allowed_builtins = {k: getattr(builtins, k) for k in ['dict', 'len', 'list', 'str', 'int']}
            namespace = {'__builtins__': allowed_builtins}
            
            exec(compile(code, '<string>', 'exec'), namespace)
            
            if class_name not in namespace:
                raise ReflectionError(f"Class '{class_name}' not found in the provided code.")
                
            cls = namespace[class_name]
            
            self.dynamic_classes[class_name] = (cls, time.time())
            return cls
            
        except Exception as e:
            logger.error(f"Error loading class '{class_name}': {e}", exc_info=True)
            raise ReflectionError(f"Class loading failed: {str(e)}") from e

    async def _check_code_safety(self, code: str) -> bool:
        dangerous_patterns = [
            "exec(", "eval(", "import os", "import sys",
            "subprocess", "__import__", "open(", "file("
        ]
        for pattern in dangerous_patterns:
            if pattern in code:
                raise ReflectionError(f"Unsafe code pattern detected: {pattern}")

        lines = code.split("\n")
        if len(lines) > 10_000:
            raise ReflectionError("Code is too large or complex.")

        return True

    @property
    def cache_stats(self) -> Dict[str, int]:
        return {
            "modules": len(self.loaded_modules),
            "classes": len(self.dynamic_classes),
            "methods": len(self.method_cache),
            "bytecode": len(self.bytecode_cache)
        }

    async def introspect_code(self, code: str) -> Dict[str, Any]:
        try:
            tree = ast.parse(code)
            analysis = {
                "imports": [],
                "classes": [],
                "functions": [],
                "complexity": 0
            }
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    analysis["imports"].extend(n.name for n in node.names)
                elif isinstance(node, ast.ClassDef):
                    analysis["classes"].append(node.name)
                elif isinstance(node, ast.FunctionDef):
                    analysis["functions"].append(node.name)
                analysis["complexity"] += 1
                
            return analysis
            
        except Exception as e:
            logger.error(f"Code introspection failed: {e}", exc_info=True)
            raise ReflectionError(f"Introspection failed: {str(e)}") from e

    async def get_method(self, cls: type, method_name: str) -> Optional[Callable]:
        try:
            cache_key = f"{cls.__name__}.{method_name}"
            
            if cache_key in self.method_cache:
                return self.method_cache[cache_key][0]
                
            method = getattr(cls, method_name, None)
            if not method:
                raise ReflectionError(f"Method '{method_name}' not found in class '{cls.__name__}'.")
                
            self.method_cache[cache_key] = (method, time.time())
            return method
            
        except Exception as e:
            logger.error(f"Error getting method '{method_name}' from '{cls.__name__}': {e}", exc_info=True)
            raise ReflectionError(f"Method access failed: {str(e)}") from e

    async def execute_code(self, code: str, args: Optional[Dict[str, Any]] = None, timeout: float = 5.0) -> Any:
        try:
            await self._check_code_safety(code)
            
            return await asyncio.wait_for(
                self._async_execute(code, args or {}),
                timeout=timeout
            )
            
        except asyncio.TimeoutError:
            raise ReflectionError("Code execution timed out.")
        except Exception as e:
            logger.error(f"Code execution failed: {e}", exc_info=True)
            raise ReflectionError(f"Execution failed: {str(e)}") from e

    async def _async_execute(self, code: str, namespace: Dict[str, Any]) -> Any:
        loop = asyncio.get_event_loop()
        compiled_code = compile(code, '<string>', 'eval')
        
        import builtins
        safe_builtin_keys = ['dict', 'len', 'list', 'str', 'int']
        safe_builtins = {k: getattr(builtins, k) for k in safe_builtin_keys}
        
        return await loop.run_in_executor(
            None,
            eval,
            compiled_code,
            {'__builtins__': safe_builtins},
            namespace
        )

    def generate_dynamic_class(self, class_name: str, methods: Dict[str, str]) -> str:
        class_code = [f"class {class_name}:"]
        
        for method_name, method_code in methods.items():
            class_code.append(f"    def {method_name}(self):")
            indented_code = "\n".join(f"        {line}" for line in method_code.split("\n"))
            class_code.append(indented_code)
            
        return "\n".join(class_code)

    async def load_bytecode(self, bytecode: bytes) -> Any:
        try:
            bytecode_hash = hashlib.sha256(bytecode).hexdigest()
            
            if bytecode_hash in self.bytecode_cache:
                return self.bytecode_cache[bytecode_hash][0]
                
            code_obj = marshal.loads(bytecode)
            
            module = types.ModuleType(f"dynamic_module_{bytecode_hash}")
            exec(code_obj, module.__dict__)
            
            if len(self.bytecode_cache) > self.max_cache_size:
                self.bytecode_cache.clear()
            self.bytecode_cache[bytecode_hash] = (module, time.time())
            
            return module
            
        except Exception as e:
            logger.error(f"Bytecode loading failed: {e}", exc_info=True)
            raise ReflectionError(f"Bytecode load failed: {str(e)}") from e

    async def pickle_code(self, obj: Any) -> bytes:
        try:
            return dill.dumps(obj)
        except Exception as e:
            logger.error(f"Code pickling failed: {e}", exc_info=True)
            raise ReflectionError(f"Pickling failed: {str(e)}") from e

    async def unpickle_code(self, data: bytes) -> Any:
        try:
            return dill.loads(data)
        except Exception as e:
            logger.error(f"Code unpickling failed: {e}", exc_info=True)
            raise ReflectionError(f"Unpickling failed: {str(e)}") from e

    def cleanup(self, force: bool = False) -> None:
        if force:
            self.method_cache.clear()
            self.bytecode_cache.clear()
            self.loaded_modules.clear()
            self.dynamic_classes.clear()
            return

        current_time = time.time()
        
        self.loaded_modules = {
            k: v for k, v in self.loaded_modules.items()
            if self._is_cache_valid(v[1])
        }
        self.dynamic_classes = {
            k: v for k, v in self.dynamic_classes.items()
            if self._is_cache_valid(v[1])
        }
        self.method_cache = {
            k: v for k, v in self.method_cache.items()
            if self._is_cache_valid(v[1])
        }
        self.bytecode_cache = {
            k: v for k, v in self.bytecode_cache.items()
            if self._is_cache_valid(v[1])
        }

    async def validate_apk_class(self, class_name: str, apk_path: str) -> bool:
        try:
            dex_command = f"dexdump {apk_path} | grep {class_name}"
            result = await async_run_shell_command(dex_command)
            return bool(result.strip())
        except Exception as e:
            logger.error(f"APK class validation failed: {e}", exc_info=True)
            return False

    def remove_class(self, class_name: str) -> bool:
        if class_name in self.dynamic_classes:
            del self.dynamic_classes[class_name]
            return True
        return False

    async def register_dependency(self, name: str, factory: Callable[[], Any], lazy: bool = False) -> None:
        if lazy:
            self.lazy_modules[name] = factory
        else:
            self.container[name] = await factory()
        logger.info(f"Registered dependency: {name} (lazy: {lazy})")

    async def inject_dependencies(self, cls: type) -> None:
        hints = get_type_hints(cls)
        for attr, hint in hints.items():
            if hasattr(cls, attr) and isinstance(getattr(cls, attr), Inject):
                if hint.__name__ in self.container:
                    setattr(cls, attr, self.container[hint.__name__])
                elif hint.__name__ in self.lazy_modules:
                    setattr(cls, attr, await self.lazy_modules[hint.__name__]())

    def update_cache_config(self, cache_ttl: int, max_cache_size: int) -> None:
        self.cache_ttl = cache_ttl
        self.max_cache_size = max_cache_size
        self.loaded_modules.clear()
        self.dynamic_classes.clear()
        self.method_cache.clear()
        self.bytecode_cache.clear()

    async def shutdown(self) -> None:
        try:
            self.cleanup(force=True)
            self.container.clear()
            self.lazy_modules.clear()
            self.tracked_dependencies.clear()
            logger.info("ReflectionManager shutdown complete")
        except Exception as e:
            logger.error(f"Error during shutdown: {e}", exc_info=True)


class Inject:
    pass
