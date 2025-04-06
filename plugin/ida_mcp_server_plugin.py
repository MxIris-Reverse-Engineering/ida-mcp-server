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

# Function to automatically scan and register core methods
def register_core_tools(core: IDAMCPCore) -> None:
    """
    Scans IDAMCPCore instance and registers all methods decorated with @ida_tool
    
    Args:
        core: The IDAMCPCore instance
    """
    core_methods = dir(core)
    
    for tool_name, metadata in list(_tool_metadata.items()):
        method_name = metadata.get("core_method")
        
        # If this is a core method and it exists in the core instance
        if method_name and method_name in core_methods:
            # Create a wrapper function that will call the core method
            def create_wrapper(method_name):
                def wrapper(**kwargs):
                    # Get the method from the core instance
                    method = getattr(core, method_name)
                    # Call it with the given parameters
                    return method(**kwargs)
                return wrapper
            
            # Register the wrapper function
            wrapper = create_wrapper(method_name)
            wrapper.__name__ = method_name
            wrapper.__doc__ = metadata.get("description")
            
            # Replace the original registration with the wrapper
            _tool_registry[tool_name] = wrapper
            log_info(f"Registered core method {method_name} as tool {tool_name}")

# -------------------------------------------------------------------
# Tool Request Models
# -------------------------------------------------------------------

class GetFunctionAssemblyByName(BaseModel):
    function_name: str

class GetFunctionAssemblyByAddress(BaseModel):
    address: str  # Hexadecimal address as string

class GetFunctionDecompiledByName(BaseModel):
    function_name: str

class GetFunctionDecompiledByAddress(BaseModel):
    address: str  # Hexadecimal address as string

class GetGlobalVariableByName(BaseModel):
    variable_name: str

class GetGlobalVariableByAddress(BaseModel):
    address: str  # Hexadecimal address as string

class GetCurrentFunctionAssembly(BaseModel):
    pass

class GetCurrentFunctionDecompiled(BaseModel):
    pass

class RenameLocalVariable(BaseModel):
    function_name: str
    old_name: str
    new_name: str

class RenameGlobalVariable(BaseModel):
    old_name: str
    new_name: str

class RenameFunction(BaseModel):
    old_name: str
    new_name: str

class RenameMultiLocalVariables(BaseModel):
    function_name: str
    rename_pairs_old2new: List[Dict[str, str]]  # List of dictionaries with "old_name" and "new_name" keys

class RenameMultiGlobalVariables(BaseModel):
    rename_pairs_old2new: List[Dict[str, str]]

class RenameMultiFunctions(BaseModel):
    rename_pairs_old2new: List[Dict[str, str]]

class AddAssemblyComment(BaseModel):
    address: str  # Can be a hexadecimal address string
    comment: str
    is_repeatable: bool = False  # Whether the comment should be repeatable

class AddFunctionComment(BaseModel):
    function_name: str
    comment: str
    is_repeatable: bool = False  # Whether the comment should be repeatable

class AddPseudocodeComment(BaseModel):
    function_name: str
    address: str  # Address in the pseudocode
    comment: str
    is_repeatable: bool = False  # Whether comment should be repeated at all occurrences

class ExecuteScript(BaseModel):
    script: str

class ExecuteScriptFromFile(BaseModel):
    file_path: str

class MCPToolDefinition:
    """Represents a tool definition that can be sent to the MCP server"""
    
    def __init__(self, name: str, description: str, input_schema: Dict[str, Any]):
        self.name = name
        self.description = description
        self.input_schema = input_schema
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema
        }

class IDATools(str, Enum):
    """Enum of available IDA tools to be exposed to MCP"""
    GET_FUNCTION_ASSEMBLY_BY_NAME = "ida_get_function_assembly_by_name"
    GET_FUNCTION_ASSEMBLY_BY_ADDRESS = "ida_get_function_assembly_by_address"
    GET_FUNCTION_DECOMPILED_BY_NAME = "ida_get_function_decompiled_by_name"
    GET_FUNCTION_DECOMPILED_BY_ADDRESS = "ida_get_function_decompiled_by_address"
    GET_GLOBAL_VARIABLE_BY_NAME = "ida_get_global_variable_by_name"
    GET_GLOBAL_VARIABLE_BY_ADDRESS = "ida_get_global_variable_by_address"
    GET_CURRENT_FUNCTION_ASSEMBLY = "ida_get_current_function_assembly"
    GET_CURRENT_FUNCTION_DECOMPILED = "ida_get_current_function_decompiled"
    RENAME_LOCAL_VARIABLE = "ida_rename_local_variable"
    RENAME_GLOBAL_VARIABLE = "ida_rename_global_variable"
    RENAME_FUNCTION = "ida_rename_function"
    RENAME_MULTI_LOCAL_VARIABLES = "ida_rename_multi_local_variables"
    RENAME_MULTI_GLOBAL_VARIABLES = "ida_rename_multi_global_variables"
    RENAME_MULTI_FUNCTIONS = "ida_rename_multi_functions"
    ADD_ASSEMBLY_COMMENT = "ida_add_assembly_comment"
    ADD_FUNCTION_COMMENT = "ida_add_function_comment"
    ADD_PSEUDOCODE_COMMENT = "ida_add_pseudocode_comment"
    EXECUTE_SCRIPT = "ida_execute_script"
    EXECUTE_SCRIPT_FROM_FILE = "ida_execute_script_from_file"

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
                
                # Get the function's type hints
                type_hints = get_type_hints(func)
                
                # Remove return annotation if present
                type_hints.pop("return", None)
                
                # Convert and validate parameters
                kwargs = {}
                
                # For each parameter in the function signature
                for param_name, expected_type in type_hints.items():
                    if param_name in data:
                        value = data[param_name]
                        # Try to convert to expected type if needed
                        if not isinstance(value, expected_type) and expected_type != Any:
                            try:
                                # Handle special case for addresses
                                if param_name == "address" and isinstance(value, str):
                                    if value.startswith("0x"):
                                        value = int(value, 16)
                                    else:
                                        value = int(value)
                                else:
                                    value = expected_type(value)
                            except (ValueError, TypeError):
                                return ResponseFormatter.format_error_response(
                                    f"Invalid type for parameter '{param_name}': expected {expected_type.__name__}"
                                )
                        kwargs[param_name] = value
                
                # Call the function with the prepared parameters
                result = func(**kwargs)
                
                # Ensure the result is a dict with at least success field
                if not isinstance(result, dict):
                    result = {"success": True, "result": result}
                if "success" not in result:
                    result["success"] = True
                    
                return result
            else:
                # Try to use core methods directly if no registered tool found
                # This provides backward compatibility with the old system
                method_name = base_tool_name
                if hasattr(self.core, method_name) and callable(getattr(self.core, method_name)):
                    method = getattr(self.core, method_name)
                    result = method(**data)
                    return result
                
                log_warning(f"No tool found for {full_tool_name}")
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
            
            # Register all core methods decorated with @ida_tool
            register_core_tools(self.core)
            
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
            log_info(f"Available tools: {', '.join(tools)}")
            
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

# -------------------------------------------------------------------
# Example Tool Functions using the decorator-based approach
# -------------------------------------------------------------------

@ida_tool(description="Get assembly code for a function by its name")
def get_function_assembly_by_name(function_name: str) -> Dict[str, Any]:
    """Get assembly code for a function by its name"""
    core = IDAMCPCore()
    result = core.get_function_assembly_by_name(function_name)
    
    if "error" in result:
        return ResponseFormatter.format_error_response(result["error"])
    return ResponseFormatter.format_assembly_response(function_name, result.get("assembly", ""))

@ida_tool(description="Get assembly code for a function by its address")
def get_function_assembly_by_address(address: str) -> Dict[str, Any]:
    """Get assembly code for a function by its address"""
    core = IDAMCPCore()
    
    # Convert string address to int
    try:
        addr_int = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address)
    except ValueError:
        return ResponseFormatter.format_error_response(f"Invalid address format '{address}', expected hexadecimal (0x...) or decimal")
    
    result = core.get_function_assembly_by_address(addr_int)
    
    if "error" in result:
        return ResponseFormatter.format_error_response(result["error"])
    return ResponseFormatter.format_assembly_response(result.get("function_name", "Unknown"), result.get("assembly", ""))

@ida_tool(description="Rename a function")
def rename_function(old_name: str, new_name: str) -> Dict[str, Any]:
    """Rename a function"""
    core = IDAMCPCore()
    
    if not old_name:
        return ResponseFormatter.format_error_response("Old function name not provided")
    if not new_name:
        return ResponseFormatter.format_error_response("New function name not provided")
    
    result = core.rename_function(old_name, new_name)
    
    return ResponseFormatter.format_rename_response(
        result.get("success", False),
        result.get("message", ""),
        "rename_function"
    )

@ida_tool(description="Add a comment to assembly code at the specified address")
def add_assembly_comment(address: str, comment: str, is_repeatable: bool = False) -> Dict[str, Any]:
    """Add a comment to assembly code at the specified address"""
    core = IDAMCPCore()
    
    if not address:
        return ResponseFormatter.format_error_response("Address not provided")
    if not comment:
        return ResponseFormatter.format_error_response("Comment not provided")
    
    result = core.add_assembly_comment(address, comment, is_repeatable)
    
    return ResponseFormatter.format_comment_response(
        result.get("success", False),
        result.get("message", ""),
        "add_assembly_comment"
    )

@ida_tool(description="Execute a Python script in IDA Pro")
def execute_script(script: str) -> Dict[str, Any]:
    """Execute a Python script in IDA Pro"""
    core = IDAMCPCore()
    
    if not script:
        return ResponseFormatter.format_error_response("Script not provided")
    
    result = core.execute_script(script)
    
    return ResponseFormatter.format_script_response(
        result.get("success", False),
        result.get("message", ""),
        result.get("stdout", ""),
        result.get("stderr", "")
    )
