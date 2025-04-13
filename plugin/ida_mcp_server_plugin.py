import idaapi
import json
import socket
import struct
import threading
import traceback
import time
import sys
import os
from typing import Optional, Dict, Any, List, Tuple, Union, Set, Type, cast, Callable, TypeVar, get_type_hints
from ida_mcp_server_plugin.ida_mcp_core import IDAMCPCore
from pydantic import BaseModel
from enum import Enum
import functools
import inspect

PLUGIN_NAME = "IDA MCP Server"
PLUGIN_HOTKEY = "Ctrl-Alt-M"
PLUGIN_VERSION = "1.0"
PLUGIN_AUTHOR = "IDA MCP"

# Default configuration
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 5000

# -------------------------------------------------------------------
# Tool Registry System
# -------------------------------------------------------------------

# Dictionary to store registered tool functions
_tool_registry: Dict[str, Callable] = {}
_tool_metadata: Dict[str, Dict[str, Any]] = {}
T = TypeVar('T')

def ida_tool(tool_name: Optional[str] = None, description: Optional[str] = None):
    """
    Decorator to register a function as an IDA tool
    
    Args:
        tool_name: The name of the tool (defaults to function name prefixed with 'ida_')
        description: A description of the tool
    
    This decorator can be used both for standalone functions and for methods in IDAMCPCore.
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        nonlocal tool_name, description
        
        # Get function name, handle methods with 'self' parameter
        func_name = func.__name__
        
        # Default tool name is function name with ida_ prefix
        if tool_name is None:
            tool_name = f"ida_{func_name}"
            
        # Default description based on docstring or function name
        if description is None:
            description = func.__doc__ or f"IDA Pro tool: {func_name.replace('_', ' ')}"
        
        # Store information about the function itself for direct registration
        _tool_metadata[tool_name] = {
            "name": tool_name,
            "description": description,
            "function": func,
            "core_method": func_name,  # The actual method name in IDAMCPCore
        }
        
        # For standalone functions, register directly
        # For core methods, this will be overwritten at runtime
        _tool_registry[tool_name] = func
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
            
        return wrapper
    
    return decorator

# Export the ida_tool decorator for use in ida_mcp_core.py
# This avoids circular imports
def get_ida_tool_decorator():
    return ida_tool

# Define create_bound_wrapper function once at module level
def create_bound_wrapper(instance, meth):
    # Create a closure over the bound method
    bound_method = meth.__get__(instance, instance.__class__)
    
    # Create a wrapper that forwards all kwargs to the bound method
    def wrapper(**kwargs):
        try:
            log_debug(f"Calling bound method {meth.__name__} with kwargs: {kwargs}")
            # Debugging to verify parameters
            method_sig = inspect.signature(meth)
            log_debug(f"Actual method signature: {method_sig}")
            
            # Validate parameters against method signature
            expected_params = [p for p in method_sig.parameters if p != 'self']
            log_debug(f"Expected parameters: {expected_params}")
            log_debug(f"Received parameters: {list(kwargs.keys())}")
            
            # Check and log any missing parameters
            missing = [p for p in expected_params if p not in kwargs]
            if missing:
                log_error(f"Missing required parameters: {missing}")
                return {"success": False, "error": f"Missing required parameters: {', '.join(missing)}"}
            
            # Call the bound method with the parameters
            result = bound_method(**kwargs)
            log_debug(f"Bound method call successful")
            return result
        except Exception as e:
            log_error(f"Error in bound method {meth.__name__}: {str(e)}")
            traceback.print_exc()
            return {"success": False, "error": str(e)}
    return wrapper

def register_tools(core: Any) -> None:
    """Register all core methods as tools"""
    log_info("Registering IDA Pro core tools...")
    registered_count = 0
    
    # 从core实例获取所有可调用方法
    core_members = [m for m in dir(core) if not m.startswith('__')]
    core_methods = [m for m in core_members if callable(getattr(core, m))]
    
    # 第一步：查找并注册元数据中定义的方法（旧方式）
    for tool_name, metadata in _tool_metadata.items():
        # Skip if the tool is already registered
        if tool_name in _tool_registry:
            log_debug(f"Tool {tool_name} already registered, skipping")
            continue
            
        # 从元数据中找到对应的core方法名
        method_name = metadata.get("core_method")
        
        if method_name and method_name in core_methods:
            # Get the method itself
            original_method = getattr(core, method_name)
            
            # Use the global create_bound_wrapper function
            
            # Register the wrapper function with a reference to the core instance
            wrapper = create_bound_wrapper(core, original_method)
            wrapper.__name__ = method_name
            wrapper.__doc__ = metadata.get("description")
            
            # Replace the original registration with the wrapper
            _tool_registry[tool_name] = wrapper
            log_info(f"Registered core method {method_name} as tool {tool_name}")
            registered_count += 1

    # 第二步：查找并注册所有带有__ida_tool__标记的方法（新方式）
    already_registered = set()
    for item in _tool_metadata.values():
        if "core_method" in item:
            already_registered.add(item["core_method"])
    
    for method_name in core_methods:
        # 跳过已注册和私有方法
        if method_name.startswith('_') or method_name in already_registered:
            continue
        
        try:
            method = getattr(core, method_name)
            # 检查方法是否有__ida_tool__标记
            if callable(method) and hasattr(method, "__ida_tool__") and getattr(method, "__ida_tool__"):
                # 获取tool_name，如果方法有自定义名称则使用，否则使用默认前缀形式
                custom_tool_name = getattr(method, "__ida_tool_name__", None)
                tool_name = custom_tool_name if custom_tool_name else f"ida_{method_name}"
                
                # 获取描述
                description = getattr(method, "__ida_tool_description__", None) or method.__doc__ or f"IDA Pro tool: {method_name.replace('_', ' ')}"
                
                # 创建包装函数 - 使用绑定方法
                # Get the method itself - for clarity we obtain it again
                original_method = getattr(core, method_name)
                
                # Use the global create_bound_wrapper function
                wrapper = create_bound_wrapper(core, original_method)
                wrapper.__name__ = method_name
                wrapper.__doc__ = description
                
                # 添加到工具注册表
                _tool_registry[tool_name] = wrapper
                
                # 添加到元数据
                _tool_metadata[tool_name] = {
                    "name": tool_name,
                    "description": description,
                    "function": method,
                    "core_method": method_name
                }
                
                log_info(f"Registered marked method {method_name} as tool {tool_name}")
                registered_count += 1
        except Exception as e:
            log_error(f"Error registering method {method_name}: {str(e)}")
            traceback.print_exc()
    
    log_info(f"Total registered tools: {registered_count}")

    # 补充：如果注册工具数量为0，这是一个明显的问题
    if registered_count == 0:
        log_error("No tools were registered! This is likely an error with the decorator mechanism.")
        
        # 尝试列出所有可能的工具方法进行诊断
        potential_tools = []
        for method_name in core_methods:
            if not method_name.startswith('_'):
                try:
                    method = getattr(core, method_name)
                    if callable(method):
                        attrs = []
                        if hasattr(method, "__ida_tool__"):
                            attrs.append("__ida_tool__=" + str(getattr(method, "__ida_tool__")))
                        if hasattr(method, "__ida_tool_description__"):
                            attrs.append("has __ida_tool_description__")
                        if hasattr(method, "__ida_tool_name__"):
                            attrs.append("has __ida_tool_name__")
                            
                        potential_tools.append(f"{method_name} [{', '.join(attrs)}]")
                except:
                    pass
                    
        if potential_tools:
            log_info(f"Potential tool methods found (but not registered): {', '.join(potential_tools)}")
        else:
            log_info("No potential tool methods found with any __ida_tool__ attributes")

# -------------------------------------------------------------------
# Tool Request Models
# -------------------------------------------------------------------

# Setup basic logging
def log_info(message: str) -> None:
    """Log info message"""
    print(f"[INFO] {message}")

def log_debug(message: str) -> None:
    """Log debug message"""
    print(f"[DEBUG] {message}")

def log_error(message: str) -> None:
    """Log error message"""
    print(f"[ERROR] {message}")
    
def log_warning(message: str) -> None:
    """Log warning message"""
    print(f"[WARNING] {message}")

# -------------------------------------------------------------------
# Response Formatter for tool results
# -------------------------------------------------------------------

class ResponseFormatter:
    """Format tool responses for MCP protocol"""
    
    @staticmethod
    def format_assembly_response(function_name: str, assembly: str) -> Dict[str, Any]:
        """Format assembly response"""
        return {
            "success": True,
            "formatted_response": f"Assembly code for function '{function_name}':\n{assembly}"
        }
    
    @staticmethod
    def format_decompiled_response(function_name: str, decompiled_code: str) -> Dict[str, Any]:
        """Format decompiled code response"""
        return {
            "success": True,
            "formatted_response": f"Decompiled code for function '{function_name}':\n{decompiled_code}"
        }
    
    @staticmethod
    def format_variable_info_response(variable_info: str) -> Dict[str, Any]:
        """Format variable info response"""
        return {
            "success": True,
            "formatted_response": variable_info
        }
    
    @staticmethod
    def format_rename_response(success: bool, message: str, tool_name: str) -> Dict[str, Any]:
        """Format rename operation response"""
        status = "Successfully" if success else "Failed to"
        return {
            "success": success,
            "formatted_response": f"{status} {tool_name.replace('_', ' ')}: {message}"
        }
    
    @staticmethod
    def format_comment_response(success: bool, message: str, tool_name: str) -> Dict[str, Any]:
        """Format comment operation response"""
        status = "Successfully" if success else "Failed to"
        return {
            "success": success,
            "formatted_response": f"{status} {tool_name.replace('_', ' ')}: {message}"
        }
    
    @staticmethod
    def format_script_response(success: bool, message: str, stdout: str = "", stderr: str = "") -> Dict[str, Any]:
        """Format script execution response"""
        result_text = ["Script execution"]
        
        if success:
            result_text[0] += " successful"
        else:
            result_text[0] += " failed"
        
        if message:
            result_text.append(f"\nMessage: {message}")
        if stdout:
            result_text.append(f"\nStandard output:\n{stdout}")
        if stderr:
            result_text.append(f"\nStandard error:\n{stderr}")
        
        return {
            "success": success,
            "formatted_response": "\n".join(result_text)
        }
    
    @staticmethod
    def format_error_response(error_message: str) -> Dict[str, Any]:
        """Format error response"""
        return {
            "success": False,
            "error": error_message
        }

# -------------------------------------------------------------------
# Tool Executor
# -------------------------------------------------------------------

class ToolExecutor:
    """Executes tools registered with @ida_tool decorator"""
    
    def __init__(self, core: IDAMCPCore):
        """Initialize tool executor with core"""
        self.core = core
        
    def execute_tool(self, tool_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a registered tool with the given data"""
        # Add ida_ prefix if not already present
        full_tool_name = tool_name if tool_name.startswith("ida_") else f"ida_{tool_name}"
        
        # Get the base name without ida_ prefix for checking the registry
        base_tool_name = tool_name.replace("ida_", "")
        full_tool_name = f"ida_{base_tool_name}"
        
        try:
            log_info(f"Executing tool {full_tool_name}")
            
            # Check if tool exists in registry
            if full_tool_name in _tool_registry:
                func = _tool_registry[full_tool_name]
                
                log_info(f"Found registered tool {full_tool_name}: {func.__name__}")
                
                # Get the function's type hints
                type_hints = get_type_hints(func)
                
                # Remove return annotation if present
                type_hints.pop("return", None)
                
                log_debug(f"Tool {full_tool_name} expects parameters: {', '.join(type_hints.keys())}")
                log_debug(f"Received parameters: {', '.join(data.keys())}")
                
                # Convert and validate parameters
                kwargs = {}
                log_debug(f"Data dictionary contains: {data}")

                try:
                    # Get method signature directly to see all expected parameters
                    original_method = None
                    method_sig = None
                    if full_tool_name in _tool_metadata:
                        core_method_name = _tool_metadata[full_tool_name].get("core_method")
                        if core_method_name:
                            original_method = getattr(self.core, core_method_name, None)
                    
                    if original_method:
                        method_sig = inspect.signature(original_method)
                        expected_params = [p for p in method_sig.parameters if p != 'self']
                        log_debug(f"Original method signature: {method_sig}")
                        log_debug(f"Expected parameters from method signature: {expected_params}")
                    else:
                        # Fallback: inspect the wrapper function if original not found (less reliable)
                        method_sig = inspect.signature(func)
                        log_warning(f"Could not find original method, using wrapper signature: {method_sig}")

                    # For each parameter in the determined method signature
                    for param_name, param_details in method_sig.parameters.items():
                        if param_name == 'self':  # Skip self if it's a method
                            continue

                        log_debug(f"Processing parameter '{param_name}' (expected type: {param_details.annotation})")
                        
                        expected_type = param_details.annotation if param_details.annotation != inspect.Parameter.empty else Any
                        
                        # Find the parameter value in the input data (case-insensitive check included)
                        value = None
                        found_in_data = False
                        if param_name in data:
                            value = data[param_name]
                            found_in_data = True
                            log_debug(f"Found parameter in data: '{param_name}' = {value} (type: {type(value).__name__})")
                        else:
                             # Case-insensitive fallback
                            for data_key in data:
                                if data_key.lower() == param_name.lower():
                                    value = data[data_key]
                                    found_in_data = True
                                    log_warning(f"Found parameter with different case: '{data_key}' used for '{param_name}'")
                                    break
                        
                        if found_in_data:
                             # Try to convert to expected type if needed
                            if expected_type != Any:
                                if expected_type == int and isinstance(value, str):
                                    # Special handling for addresses and integers
                                    try:
                                        if value.startswith("0x"):
                                            value = int(value, 16)
                                            log_debug(f"Converted hex string to int: {value}")
                                        else:
                                            # Check if it might be a hex without 0x prefix
                                            if any(c in "abcdefABCDEF" for c in value):
                                                value = int(value, 16)
                                                log_debug(f"Converted implied hex string to int: {value}")
                                            else:
                                                value = int(value)
                                                log_debug(f"Converted decimal string to int: {value}")
                                    except ValueError as ve:
                                        error_msg = f"Invalid value for '{param_name}': '{value}' - {str(ve)}"
                                        log_error(error_msg)
                                        return ResponseFormatter.format_error_response(error_msg)
                                elif not isinstance(value, expected_type):
                                    try:
                                        # Handle bool conversion specifically
                                        if expected_type == bool and isinstance(value, str):
                                            value = value.lower() in ['true', '1', 't', 'y', 'yes']
                                        else:
                                            value = expected_type(value)
                                        log_debug(f"Converted {type(value).__name__} to {expected_type.__name__}")
                                    except (ValueError, TypeError) as e:
                                        error_msg = f"Invalid type for parameter '{param_name}': expected {expected_type.__name__}, got {type(value).__name__} - {str(e)}"
                                        log_error(error_msg)
                                        return ResponseFormatter.format_error_response(error_msg)
                            
                            kwargs[param_name] = value
                            log_debug(f"Set parameter '{param_name}' to {value}")
                        elif param_details.default is not inspect.Parameter.empty:
                            # Use default value if parameter not found in data
                            log_debug(f"Using default value for optional parameter '{param_name}'")
                            kwargs[param_name] = param_details.default # Add default value to kwargs
                        else:
                            # If parameter is required but not found and has no default
                            error_msg = f"Missing required parameter '{param_name}' for tool {full_tool_name}"
                            log_error(error_msg)
                            return ResponseFormatter.format_error_response(error_msg)
                except Exception as param_error:
                    log_error(f"Error processing parameters: {str(param_error)}")
                    traceback.print_exc()
                    return ResponseFormatter.format_error_response(f"Error processing parameters: {str(param_error)}")

                # Double check that all required parameters are present (redundant now, but safe)
                required_params_missing = []
                if method_sig:
                    for param_name, param_details in method_sig.parameters.items():
                        if param_name != 'self' and param_details.default is inspect.Parameter.empty and param_name not in kwargs:
                            required_params_missing.append(param_name)
                
                if required_params_missing:
                    error_msg = f"Internal check failed: Missing required parameters after processing: {', '.join(required_params_missing)}"
                    log_error(error_msg)
                    return ResponseFormatter.format_error_response(error_msg)

                # Call the function with the prepared parameters
                log_info(f"Calling {full_tool_name} with parameters: {', '.join([f'{k}={v}' for k, v in kwargs.items()])}") # Log should now show parameters
                try:
                    log_debug(f"Function object: {func.__name__}, callable: {callable(func)}")
                    
                    # Inspect the function signature
                    try:
                        sig = inspect.signature(func)
                        log_debug(f"Function signature: {sig}")
                        
                        # Check if the function has a 'self' parameter
                        params = list(sig.parameters.keys())
                        has_self = len(params) > 0 and params[0] == 'self'
                        log_debug(f"Function has 'self' parameter: {has_self}")
                    except Exception as sig_error:
                        log_warning(f"Could not inspect function signature: {str(sig_error)}")
                    
                    # Call the function
                    result = func(**kwargs)
                    log_debug(f"Function call successful, result type: {type(result).__name__}")
                except Exception as call_error:
                    error_msg = f"Error calling {full_tool_name}: {str(call_error)}"
                    log_error(error_msg)
                    traceback.print_exc()
                    return ResponseFormatter.format_error_response(error_msg)
                
                # Ensure the result is a dict with at least success field
                if not isinstance(result, dict):
                    result = {"success": True, "result": result}
                if "success" not in result:
                    result["success"] = True
                    
                log_info(f"Tool {full_tool_name} executed successfully: {result.get('success', True)}")
                return result
            else:
                # Try to use core methods directly if no registered tool found
                # This provides backward compatibility with the old system
                method_name = base_tool_name
                if hasattr(self.core, method_name) and callable(getattr(self.core, method_name)):
                    log_info(f"No registered tool found for {full_tool_name}, attempting direct core method call")
                    method = getattr(self.core, method_name)
                    
                    # Check if the method has the __ida_tool__ attribute
                    has_tool_attr = hasattr(method, "__ida_tool__") and getattr(method, "__ida_tool__")
                    log_debug(f"Direct method {method_name} has __ida_tool__ attribute: {has_tool_attr}")
                    
                    # Call the method directly
                    try:
                        log_debug(f"Direct call to method {method_name}, callable: {callable(method)}")
                        
                        # Inspect the method signature
                        try:
                            sig = inspect.signature(method)
                            log_debug(f"Method signature: {sig}")
                            
                            # Check if the method has a 'self' parameter
                            params = list(sig.parameters.keys())
                            has_self = len(params) > 0 and params[0] == 'self'
                            log_debug(f"Method has 'self' parameter: {has_self}")
                            
                            # Process parameters for the direct call
                            kwargs = {}
                            for param_name, param in sig.parameters.items():
                                if param_name == 'self':
                                    continue  # Skip self parameter
                                    
                                # Check if parameter is in the data dictionary
                                if param_name in data:
                                    value = data[param_name]
                                    log_debug(f"Found parameter in data: '{param_name}' = {value}")
                                    
                                    # Try to convert the parameter if needed
                                    param_type = param.annotation if param.annotation != inspect.Parameter.empty else None
                                    if param_type is not None and param_type != Any:
                                        if param_type == int and isinstance(value, str):
                                            # Special handling for addresses and integers
                                            try:
                                                if value.startswith("0x"):
                                                    value = int(value, 16)
                                                    log_debug(f"Converted hex string to int: '{value}'")
                                                else:
                                                    # Check if it might be a hex without 0x prefix
                                                    if any(c in "abcdefABCDEF" for c in value):
                                                        value = int(value, 16)
                                                        log_debug(f"Converted implied hex string to int: '{value}'")
                                                    else:
                                                        value = int(value)
                                                        log_debug(f"Converted decimal string to int: '{value}'")
                                            except ValueError as ve:
                                                return ResponseFormatter.format_error_response(
                                                    f"Invalid value for '{param_name}': '{value}' - {str(ve)}"
                                                )
                                        elif not isinstance(value, param_type):
                                            try:
                                                value = param_type(value)
                                                log_debug(f"Converted {type(value).__name__} to {param_type.__name__}")
                                            except (ValueError, TypeError) as e:
                                                return ResponseFormatter.format_error_response(
                                                    f"Invalid type for parameter '{param_name}': expected {param_type.__name__}, got {type(value).__name__} - {str(e)}"
                                                )
                                    
                                    kwargs[param_name] = value
                                else:
                                    # Check for case-insensitive match
                                    found = False
                                    for data_key in data:
                                        if data_key.lower() == param_name.lower():
                                            value = data[data_key]
                                            log_debug(f"Found parameter with different case: '{data_key}' = {value}")
                                            kwargs[param_name] = value
                                            found = True
                                            break
                                    
                                    # Check if parameter has a default value
                                    if not found and param.default != inspect.Parameter.empty:
                                        log_debug(f"Using default value for optional parameter '{param_name}'")
                                        continue
                                    elif not found:
                                        missing_param = param_name
                                        log_error(f"Missing required parameter for direct method call: {missing_param}")
                                        return ResponseFormatter.format_error_response(
                                            f"Missing required parameter: {missing_param}"
                                        )
                            
                            # Log what we're going to call with
                            log_debug(f"Calling direct method with kwargs: {kwargs}")
                            
                            # Create a bound method to ensure 'self' is properly passed
                            bound_method = method.__get__(self.core, self.core.__class__)
                            result = bound_method(**kwargs)
                            log_info(f"Direct call to {method_name} successful")
                            return result
                        except Exception as sig_error:
                            log_warning(f"Could not inspect method signature: {str(sig_error)}")
                            # Fall back to using the original data dictionary
                            bound_method = method.__get__(self.core, self.core.__class__)
                            result = bound_method(**data)
                            log_info(f"Direct call to {method_name} successful (using fallback)")
                            return result
                    except Exception as direct_error:
                        error_msg = f"Error in direct call to {method_name}: {str(direct_error)}"
                        log_error(error_msg)
                        traceback.print_exc()
                        return ResponseFormatter.format_error_response(error_msg)
                
                # Log available tools for debugging
                available_tools = list(_tool_registry.keys())
                log_warning(f"No tool found for {full_tool_name}. Available tools: {', '.join(available_tools)}")
                return ResponseFormatter.format_error_response(f"Tool not found: {full_tool_name}")
                
        except Exception as e:
            log_error(f"Error executing tool {full_tool_name}: {str(e)}")
            traceback.print_exc()
            return ResponseFormatter.format_error_response(f"Error executing {full_tool_name}: {str(e)}")
    
    def get_all_tools(self) -> List[Dict[str, Any]]:
        """Get list of all registered tools with their metadata"""
        tools = []
        
        for tool_name, metadata in _tool_metadata.items():
            function = metadata["function"]
            
            # Get parameter information from type hints
            type_hints = get_type_hints(function)
            type_hints.pop("return", None)  # Remove return annotation
            
            # Create schema for the tool
            properties = {}
            required = []
            
            for param_name, param_type in type_hints.items():
                # Convert Python types to JSON schema types
                json_type = "string"
                if param_type == int:
                    json_type = "integer"
                elif param_type == float:
                    json_type = "number"
                elif param_type == bool:
                    json_type = "boolean"
                elif param_type == List[str]:
                    json_type = "array"
                
                # Add parameter to properties
                properties[param_name] = {
                    "type": json_type,
                    "description": f"Parameter: {param_name}"
                }
                
                # Add to required list (we assume all parameters are required for now)
                required.append(param_name)
            
            # Create input schema
            input_schema = {
                "type": "object",
                "properties": properties,
                "required": required
            }
            
            # Create tool definition
            tool_def = {
                "name": tool_name,
                "description": metadata["description"],
                "inputSchema": input_schema
            }
            
            tools.append(tool_def)
        
        return tools
        
    def get_tool_names(self) -> List[str]:
        """Get list of all registered tool names"""
        return list(_tool_registry.keys())

# -------------------------------------------------------------------
# Socket Server for MCP Protocol Communication
# -------------------------------------------------------------------

class SocketServer:
    """Socket server for MCP protocol communication"""
    
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, tool_executor: ToolExecutor = None):
        self.host: str = host
        self.port: int = port
        self.server_socket: Optional[socket.socket] = None
        self.running: bool = False
        self.thread: Optional[threading.Thread] = None
        self.client_counter: int = 0
        self.tool_executor = tool_executor
        
        # Check environment variables for configuration
        if 'IDA_MCP_HOST' in os.environ:
            self.host = os.environ['IDA_MCP_HOST']
            log_info(f"Using host from environment: {self.host}")
            
        if 'IDA_MCP_PORT' in os.environ:
            try:
                self.port = int(os.environ['IDA_MCP_PORT'])
                log_info(f"Using port from environment: {self.port}")
            except ValueError:
                log_warning(f"Invalid port in environment: {os.environ['IDA_MCP_PORT']}, using default: {self.port}")

    def start(self) -> bool:
        """Start the server"""
        if self.running:
            log_info("Server is already running")
            return True
        
        try:
            # Create socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to host and port
            self.server_socket.bind((self.host, self.port))
            
            # Set socket to non-blocking
            self.server_socket.setblocking(0)
            
            # Listen for connections
            self.server_socket.listen(5)
            
            # Start server thread
            self.running = True
            self.thread = threading.Thread(target=self.server_loop, name=f"MCP-Server-{id(self)}")
            self.thread.daemon = True
            self.thread.start()
            
            log_info(f"Server started on {self.host}:{self.port}")
            return True
        except OSError as e:
            if e.errno == 10048:  # Port already in use
                log_error(f"Port {self.port} is already in use")
            else:
                log_error(f"OS error when starting server: {str(e)}")
            return False
        except Exception as e:
            log_error(f"Error starting server: {str(e)}")
            traceback.print_exc()
            return False
    
    def stop(self) -> None:
        """Stop the server"""
        if not self.running:
            return
        
        self.running = False
        
        try:
            # Close server socket
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            
            # Wait for server thread to terminate
            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=3.0)
                if self.thread.is_alive():
                    log_warning("Server thread did not terminate cleanly")
            
            log_info("Server stopped")
        except Exception as e:
            log_error(f"Error stopping server: {str(e)}")
            traceback.print_exc()

    def send_message(self, client_socket: socket.socket, data: bytes) -> None:
        """Send message with length prefix"""
        # Prepend message length
        length: int = len(data)
        length_bytes: bytes = struct.pack('!I', length)  # 4-byte length prefix in network order
        
        # Send length prefix and data
        client_socket.sendall(length_bytes + data)
    
    def receive_message(self, client_socket: socket.socket) -> bytes:
        """Receive message with length prefix"""
        # Receive message length (4 bytes)
        length_bytes: bytes = self.receive_exactly(client_socket, 4)
        
        # Parse message length
        length: int = struct.unpack('!I', length_bytes)[0]
        
        # Validate message length (prevent malicious large messages)
        if length > 100 * 1024 * 1024:  # 100 MB
            raise ValueError(f"Message too large: {length} bytes")
        
        # Receive message data
        data: bytes = self.receive_exactly(client_socket, length)
        
        return data
    
    def receive_exactly(self, client_socket: socket.socket, n: int) -> bytes:
        """Receive exactly n bytes from socket"""
        data: bytes = b''
        remaining: int = n
        
        while remaining > 0:
            chunk: bytes = client_socket.recv(remaining)
            if not chunk:  # Connection closed
                raise ConnectionError("Connection closed while receiving data")
            
            data += chunk
            remaining -= len(chunk)
        
        return data

    def server_loop(self) -> None:
        """Main server loop"""
        if not self.server_socket:
            log_error("Server socket not initialized")
            return
        
        try:
            while self.running:
                try:
                    # Check for new connections (non-blocking)
                    try:
                        client_socket, client_address = self.server_socket.accept()
                        log_info(f"New client connected from {client_address[0]}:{client_address[1]}")
                        
                        # Increment client counter
                        self.client_counter += 1
                        
                        # Start client thread
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, self.client_counter),
                            name=f"MCP-Client-{self.client_counter}"
                        )
                        client_thread.daemon = True
                        client_thread.start()
                    except BlockingIOError:
                        # No new connections, continue
                        pass
                except Exception as e:
                    if self.running:
                        log_error(f"Error accepting connection: {str(e)}")
                
                # Small sleep to prevent CPU hogging
                time.sleep(0.1)
                
        except Exception as e:
            if self.running:
                log_error(f"Error in server loop: {str(e)}")
                traceback.print_exc()
        finally:
            self.running = False
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
                self.server_socket = None
            log_info("Server loop terminated")
    
    def handle_client(self, client_socket: socket.socket, client_id: int) -> None:
        """Handle client requests"""
        try:
            # Set timeout
            client_socket.settimeout(30)
            
            while self.running:
                try:
                    # Receive message
                    data: bytes = self.receive_message(client_socket)
                    
                    # Parse request
                    request: Dict[str, Any] = json.loads(data.decode('utf-8'))
                    request_type: str = request.get('type', '')
                    request_data: Dict[str, Any] = request.get('data', {})
                    request_id: str = request.get('id', 'unknown')
                    request_count: int = request.get('count', -1)
                    
                    log_info(f"Client #{client_id} request: {request_type}, ID: {request_id}, Count: {request_count}")
                    
                    # Create basic response
                    response: Dict[str, Any] = {
                        "id": request_id,  # Return same request ID
                        "count": request_count  # Return same request count
                    }
                    
                    # Special handling for get_tool_list request
                    if request_type == "get_tool_list":
                        try:
                            # Get tool list
                            tools = self.get_available_tool_list()
                            
                            # 验证工具列表格式正确
                            if not tools:
                                log_warning("No tools returned from get_available_tool_list")
                                tools = []
                            
                            # 检查每个工具定义是否包含必要字段
                            for i, tool in enumerate(tools[:]):
                                if not isinstance(tool, dict):
                                    log_warning(f"Tool at index {i} is not a dictionary, converting to dict")
                                    if hasattr(tool, 'to_dict'):
                                        tools[i] = tool.to_dict()
                                    else:
                                        log_error(f"Tool at index {i} cannot be converted to dict, removing")
                                        tools.remove(tool)
                                        continue
                                
                                # 确保包含所有必要字段
                                if not all(key in tool for key in ["name", "description", "inputSchema"]):
                                    log_warning(f"Tool at index {i} missing required field(s), fixing")
                                    if "name" not in tool:
                                        tool["name"] = f"unknown_tool_{i}"
                                    if "description" not in tool:
                                        tool["description"] = "No description available"
                                    if "inputSchema" not in tool:
                                        tool["inputSchema"] = {}
                            
                            # 确保整个响应结构有效
                            response["tools"] = tools
                            
                            # 验证响应是否可序列化
                            try:
                                json.dumps(response)
                                log_debug(f"Successfully validated tool list response with {len(tools)} tools")
                            except Exception as je:
                                log_error(f"Response serialization error: {str(je)}")
                                # 如果序列化失败，返回一个简单的响应
                                response = {
                                    "id": request_id,
                                    "count": request_count,
                                    "error": f"Error generating tool list: {str(je)}",
                                    "tools": []
                                }
                            
                            log_debug(f"Returning {len(tools)} available tools")
                            
                        except Exception as e:
                            log_error(f"Error generating tool list: {str(e)}")
                            traceback.print_exc()
                            response["error"] = f"Error generating tool list: {str(e)}"
                            response["tools"] = []
                    
                    # Special handling for call_tool request
                    elif request_type == "call_tool":
                        try:
                            # Extract tool name and arguments
                            tool_name = request_data.get("tool_name", "")
                            arguments = request_data.get("arguments", {})
                            
                            if not tool_name:
                                response["error"] = "Tool name not provided"
                            else:
                                # Call the tool executor to execute the tool
                                result = self.tool_executor.execute_tool(tool_name, arguments)
                                response.update(result)
                        except Exception as e:
                            log_error(f"Error executing tool: {str(e)}")
                            traceback.print_exc()
                            response["error"] = f"Error executing tool: {str(e)}"
                    
                    # For direct tool calls (backward compatibility)
                    elif self.tool_executor:
                        try:
                            # Call the tool executor to execute the tool
                            result = self.tool_executor.execute_tool(request_type, request_data)
                            response.update(result)
                        except Exception as e:
                            log_error(f"Error executing tool {request_type}: {str(e)}")
                            traceback.print_exc()
                            response["error"] = f"Error executing {request_type}: {str(e)}"
                    else:
                        response["error"] = "Tool executor not available"
                    
                    # Ensure all values in response are serializable
                    self.sanitize_response(response)
                    
                    # Send response
                    response_json: bytes = json.dumps(response).encode('utf-8')
                    self.send_message(client_socket, response_json)
                    log_debug(f"Sent response to client #{client_id}, ID: {request_id}, Count: {request_count}")
                    
                except ConnectionError as e:
                    log_info(f"Connection with client #{client_id} lost: {str(e)}")
                    return
                except socket.timeout:
                    continue
                except json.JSONDecodeError as e:
                    log_error(f"Invalid JSON request from client #{client_id}: {str(e)}")
                    try:
                        response: Dict[str, Any] = {
                            "error": f"Invalid JSON request: {str(e)}"
                        }
                        self.send_message(client_socket, json.dumps(response).encode('utf-8'))
                    except:
                        log_error(f"Failed to send error response to client #{client_id}")
                except Exception as e:
                    log_error(f"Error processing request from client #{client_id}: {str(e)}")
                    traceback.print_exc()
                    try:
                        response: Dict[str, Any] = {
                            "error": str(e)
                        }
                        self.send_message(client_socket, json.dumps(response).encode('utf-8'))
                    except:
                        log_error(f"Failed to send error response to client #{client_id}")
                
        except Exception as e:
            log_error(f"Error handling client #{client_id}: {str(e)}")
            traceback.print_exc()
        finally:
            try:
                client_socket.close()
            except:
                pass
            log_info(f"Client #{client_id} connection closed")
    
    def sanitize_response(self, response: Dict[str, Any]) -> None:
        """Ensure all values in the response are JSON serializable"""
        for key, value in list(response.items()):
            if isinstance(value, dict):
                self.sanitize_response(value)
            elif isinstance(value, (list, tuple)):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        self.sanitize_response(item)
                    elif not isinstance(item, (str, int, float, bool, type(None))):
                        value[i] = str(item)
            elif not isinstance(value, (str, int, float, bool, type(None))):
                log_warning(f"Response key '{key}' has non-serializable type: {type(value).__name__}")
                response[key] = str(value)
    
    def get_available_tool_list(self) -> List[Dict[str, Any]]:
        """Get list of available tools in the format needed by MCP"""
        try:
            if not self.tool_executor:
                log_warning("No tool executor available")
                return []
                
            # Get tools directly from the tool executor
            tool_definitions = self.tool_executor.get_all_tools()
            log_info(f"Returning {len(tool_definitions)} tools from tool executor")
            
            return tool_definitions
            
        except Exception as e:
            log_error(f"Error generating tool list: {str(e)}")
            traceback.print_exc()
            return []

# IDA Plugin class
class IDAMCPPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "IDA MCP Server Plugin"
    help = "Provides MCP server functionality for IDA"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = PLUGIN_HOTKEY
    
    def __init__(self):
        super(IDAMCPPlugin, self).__init__()
        self.core: Optional[IDAMCPCore] = None
        self.tool_executor: Optional[ToolExecutor] = None  # Use ToolExecutor instead of ServiceRegistry
        self.server: Optional[SocketServer] = None
        self.initialized: bool = False
        self.menu_items_added: bool = False
        log_info(f"IDAMCPPlugin instance created")
    
    def init(self) -> int:
        """Plugin initialization"""
        try:
            log_info(f"{PLUGIN_NAME} v{PLUGIN_VERSION} by {PLUGIN_AUTHOR}")
            log_info("Initializing plugin...")
            
            # Create core instance
            self.core = IDAMCPCore()
            log_info(f"Created IDAMCPCore instance: {self.core.__class__.__name__}")
            
            # Log available methods in core
            methods = [m for m in dir(self.core) if callable(getattr(self.core, m)) and not m.startswith('_')]
            log_info(f"Core has {len(methods)} public methods")
            log_debug(f"Core methods: {', '.join(methods)}")
            
            # Check for any methods with ida_tool attributes
            tool_methods = []
            for method_name in methods:
                method = getattr(self.core, method_name)
                if hasattr(method, "__ida_tool__") and getattr(method, "__ida_tool__"):
                    tool_methods.append(method_name)
            
            if tool_methods:
                log_info(f"Found {len(tool_methods)} methods with __ida_tool__ attribute: {', '.join(tool_methods)}")
            else:
                log_warning("No methods with __ida_tool__ attribute found before registration")
            
            # Register all core methods decorated with @ida_tool
            log_info("Registering core tools...")
            register_tools(self.core)
            
            # Create tool executor (replacing service registry)
            self.tool_executor = ToolExecutor(self.core)
            
            # Create server with tool executor
            self.server = SocketServer(tool_executor=self.tool_executor)
            
            # Add menu items
            if not self.menu_items_added:
                self.create_menu_items()
                self.menu_items_added = True
                log_info("Menu items added")
            
            # Mark as initialized
            self.initialized = True
            log_info("Plugin initialized successfully")
            
            # Log available tools
            tools = self.tool_executor.get_tool_names()
            if tools:
                log_info(f"Available tools ({len(tools)}): {', '.join(tools)}")
            else:
                log_error("No tools were registered during initialization!")
            
            # Delay server start to avoid initialization issues
            idaapi.register_timer(500, self._delayed_server_start)
            
            return idaapi.PLUGIN_KEEP
        except Exception as e:
            log_error(f"Error initializing plugin: {str(e)}")
            traceback.print_exc()
            return idaapi.PLUGIN_SKIP
    
    def _delayed_server_start(self) -> int:
        """Delayed server start to avoid initialization race conditions"""
        try:
            if not self.server or not self.server.running:
                log_info("Starting server (delayed)...")
                self.start_server()
        except Exception as e:
            log_error(f"Error in delayed server start: {str(e)}")
            traceback.print_exc()
        return -1  # Don't repeat
    
    def create_menu_items(self) -> None:
        """Create plugin menu items"""
        # Create menu items
        menu_path: str = "Edit/Plugins/"
        
        class StartServerHandler(idaapi.action_handler_t):
            def __init__(self, plugin: 'IDAMCPPlugin'):
                idaapi.action_handler_t.__init__(self)
                self.plugin: 'IDAMCPPlugin' = plugin
            
            def activate(self, ctx) -> int:
                self.plugin.start_server()
                return 1
            
            def update(self, ctx) -> int:
                return idaapi.AST_ENABLE_ALWAYS
        
        class StopServerHandler(idaapi.action_handler_t):
            def __init__(self, plugin: 'IDAMCPPlugin'):
                idaapi.action_handler_t.__init__(self)
                self.plugin: 'IDAMCPPlugin' = plugin
            
            def activate(self, ctx) -> int:
                self.plugin.stop_server()
                return 1
            
            def update(self, ctx) -> int:
                return idaapi.AST_ENABLE_ALWAYS
        
        try:
            # Register and add start server action
            start_action_name: str = "mcp:start_server"
            start_action_desc: idaapi.action_desc_t = idaapi.action_desc_t(
                start_action_name,
                "Start MCP Server",
                StartServerHandler(self),
                "Ctrl+Alt+S",
                "Start the MCP Server",
                199  # Icon ID
            )
            
            # Register and add stop server action
            stop_action_name: str = "mcp:stop_server"
            stop_action_desc: idaapi.action_desc_t = idaapi.action_desc_t(
                stop_action_name, 
                "Stop MCP Server",
                StopServerHandler(self),
                "Ctrl+Alt+X",
                "Stop the MCP Server",
                200  # Icon ID
            )
            
            # Register actions
            if not idaapi.register_action(start_action_desc):
                log_error("Failed to register start server action")
            if not idaapi.register_action(stop_action_desc):
                log_error("Failed to register stop server action")
            
            # Add to menu
            if not idaapi.attach_action_to_menu(menu_path + "Start MCP Server", start_action_name, idaapi.SETMENU_APP):
                log_error("Failed to attach start server action to menu")
            if not idaapi.attach_action_to_menu(menu_path + "Stop MCP Server", stop_action_name, idaapi.SETMENU_APP):
                log_error("Failed to attach stop server action to menu")
                
            log_info("Menu items created successfully")
        except Exception as e:
            log_error(f"Error creating menu items: {str(e)}")
            traceback.print_exc()
    
    def start_server(self) -> None:
        """Start server"""
        if self.server and self.server.running:
            log_info("MCP Server is already running")
            return
        
        try:
            if not self.server:
                self.server = SocketServer(tool_executor=self.tool_executor)
                
            log_info("Starting MCP Server...")
            if self.server.start():
                log_info("MCP Server started successfully")
                self._log_connection_info()
            else:
                log_error("Failed to start MCP Server")
        except Exception as e:
            log_error(f"Error starting server: {str(e)}")
            traceback.print_exc()
    
    def _log_connection_info(self) -> None:
        """Log connection information for MCP clients"""
        if not self.server:
            return
            
        host = self.server.host or DEFAULT_HOST
        port = self.server.port or DEFAULT_PORT
        
        log_info(f"MCP Server is listening at {host}:{port}")
        log_info("To connect, make sure MCP server is configured to use the same host and port")
        log_info("Environment variables: IDA_MCP_HOST and IDA_MCP_PORT can be used for configuration")
    
    def stop_server(self) -> None:
        """Stop server"""
        if not self.server:
            log_info("MCP Server instance does not exist")
            return
            
        if not self.server.running:
            log_info("MCP Server is not running")
            return
        
        try:
            self.server.stop()
            log_info("MCP Server stopped by user")
        except Exception as e:
            log_error(f"Error stopping server: {str(e)}")
            traceback.print_exc()
    
    def run(self, arg) -> None:
        """Execute when hotkey is pressed"""
        if not self.initialized:
            log_error("Plugin not initialized")
            return
        
        # Automatically start or stop server when hotkey is triggered
        try:
            if not self.server or not self.server.running:
                log_info("Hotkey triggered: starting server")
                self.start_server()
            else:
                log_info("Hotkey triggered: stopping server")
                self.stop_server()
        except Exception as e:
            log_error(f"Error in run method: {str(e)}")
            traceback.print_exc()
    
    def term(self) -> None:
        """Plugin termination"""
        try:
            if self.server and self.server.running:
                log_info("Terminating plugin: stopping server")
                self.server.stop()
            log_info(f"{PLUGIN_NAME} terminated")
        except Exception as e:
            log_error(f"Error terminating plugin: {str(e)}")
            traceback.print_exc()

# Register plugin
def PLUGIN_ENTRY() -> IDAMCPPlugin:
    return IDAMCPPlugin()
