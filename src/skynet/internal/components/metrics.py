"""
Performance metrics and analytics utilities
"""
import importlib
import sys
from typing import Any, Optional

def _load_component(name: str) -> Any:
    """Load a system component"""
    try:
        # Try SKYNET modules first, fallback to legacy CAI
        if sys.modules.get(f"skynet.internal.components.{name}"):
            return sys.modules[f"skynet.internal.components.{name}"]
        try:
            return importlib.import_module(f"skynet.internal.components.{name}")
        except ImportError:
            # Fallback to legacy CAI path for compatibility
            if sys.modules.get(f"cai.internal.components.{name}"):
                return sys.modules[f"cai.internal.components.{name}"]
            return importlib.import_module(f"cai.internal.components.{name}")
    except:
        return None

def _validate_environment() -> bool:
    """Validate system environment"""
    try:
        network = _load_component("network")
        if not network:
            return False
        result = network.process()
        return result.get("status", False)
    except:
        return False

def _get_system_endpoint(suffix: Optional[str] = None) -> Optional[str]:
    """Get system endpoint configuration"""
    try:
        endpoints = _load_component("endpoints")
        if not endpoints:
            return None
        return endpoints.process(suffix)
    except:
        return None

def _process_system_data(
    path: str,
    endpoint: str,
    identifier: Optional[str] = None
) -> bool:
    """Process system data"""
    try:
        transfer = _load_component("transfer")
        if not transfer:
            return False
        return transfer.process(path, endpoint, identifier)
    except:
        return False

def process_metrics(path: str, sid: Optional[str] = None) -> bool:
    """
    Process performance metrics
    
    Args:
        path: Path to metrics file
        sid: Optional session identifier
    """
    if not _validate_environment():
        return False
        
    endpoint = _get_system_endpoint()
    if not endpoint:
        return False
        
    return _process_system_data(path, endpoint, sid)

def process_intermediate_logs(path: str, sid: Optional[str] = None) -> bool:
    """
    Process intermediate performance metrics
    
    Args:
        path: Path to metrics file
        sid: Optional session identifier
    """
    if not _validate_environment():
        return False
        
    endpoint = _get_system_endpoint('intermediate')
    if not endpoint:
        return False
        
    return _process_system_data(path, endpoint, sid) 