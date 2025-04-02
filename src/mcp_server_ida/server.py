import logging
import socket
import json
import time
import struct
import uuid
import sys
import os
from typing import Dict, Any, List, Optional
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    TextContent,
    Tool,
)
from pydantic import BaseModel

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("mcp_ida_proxy")

# -------------------------------------------------------------------
# MCP Server Proxy Errors
# -------------------------------------------------------------------

class MCPProxyError(Exception):
    """Base error class for MCP proxy errors"""
    pass

class ConnectionError(MCPProxyError):
    """Error during connection to IDA plugin"""
    pass

class ResponseError(MCPProxyError):
    """Error in response from IDA plugin"""
    pass

class TimeoutError(MCPProxyError):
    """Timeout error during communication with IDA plugin"""
    pass

# -------------------------------------------------------------------
# Socket Transport for communicating with IDA Plugin
# -------------------------------------------------------------------

class IDASocketTransport:
    """Transport layer for communicating with IDA plugin via sockets"""
    
    def __init__(self, host: str = 'localhost', port: int = 5000):
        self.host: str = host
        self.port: int = port
        self.sock: Optional[socket.socket] = None
        self.connected: bool = False
        self.reconnect_attempts: int = 0
        self.max_reconnect_attempts: int = 5
        self.last_reconnect_time: float = 0
        self.reconnect_cooldown: int = 5  # seconds
        self.default_timeout: int = 10
        self.long_timeout: int = 60
        
        # Get host/port from environment if specified
        if 'IDA_MCP_HOST' in os.environ:
            self.host = os.environ['IDA_MCP_HOST']
            logger.info(f"Using host from environment: {self.host}")
        
        if 'IDA_MCP_PORT' in os.environ:
            try:
                self.port = int(os.environ['IDA_MCP_PORT'])
                logger.info(f"Using port from environment: {self.port}")
            except ValueError:
                logger.warning(f"Invalid port in environment: {os.environ['IDA_MCP_PORT']}, using default: {self.port}")
    
    def connect(self) -> bool:
        """Connect to IDA plugin socket server"""
        # Check if cooldown is needed
        current_time: float = time.time()
        if current_time - self.last_reconnect_time < self.reconnect_cooldown and self.reconnect_attempts > 0:
            logger.debug("In reconnection cooldown, skipping")
            return False
            
        # If already connected, disconnect first
        if self.connected:
            self.disconnect()
        
        try:
            logger.info(f"Connecting to IDA plugin at {self.host}:{self.port}...")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(self.default_timeout)
            self.sock.connect((self.host, self.port))
            self.connected = True
            self.reconnect_attempts = 0
            logger.info(f"Successfully connected to IDA plugin ({self.host}:{self.port})")
            return True
        except Exception as e:
            self.last_reconnect_time = current_time
            self.reconnect_attempts += 1
            if self.reconnect_attempts <= self.max_reconnect_attempts:
                logger.warning(f"Failed to connect to IDA plugin: {str(e)}. Attempt {self.reconnect_attempts}/{self.max_reconnect_attempts}")
            else:
                logger.error(f"Failed to connect to IDA plugin after {self.max_reconnect_attempts} attempts: {str(e)}")
            return False
    
    def disconnect(self) -> None:
        """Disconnect from IDA plugin socket server"""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        self.connected = False
        logger.debug("Disconnected from IDA plugin")
    
    def ensure_connection(self) -> bool:
        """Ensure connection is established"""
        if not self.connected:
            return self.connect()
        return True
    
    def send_message(self, data: bytes) -> None:
        """Send message with length prefix"""
        if self.sock is None:
            raise ConnectionError("Socket is not connected")
            
        length: int = len(data)
        length_bytes: bytes = struct.pack('!I', length)  # 4-byte length prefix
        try:
            self.sock.sendall(length_bytes + data)
        except socket.error as e:
            logger.error(f"Socket error while sending data: {str(e)}")
            self.disconnect()
            raise ConnectionError(f"Failed to send data: {str(e)}")
    
    def receive_message(self) -> bytes:
        """Receive message with length prefix"""
        try:
            # Receive 4-byte length prefix
            length_bytes: Optional[bytes] = self.receive_exactly(4)
            if not length_bytes:
                raise ConnectionError("Connection closed while receiving length prefix")
                
            length: int = struct.unpack('!I', length_bytes)[0]
            
            # Validate length to prevent malicious input
            if length > 100 * 1024 * 1024:  # 100MB limit
                raise ResponseError(f"Response too large: {length} bytes")
            
            # Receive message body
            data: Optional[bytes] = self.receive_exactly(length)
            if not data:
                raise ConnectionError("Connection closed while receiving message body")
            
            return data
        except socket.timeout:
            logger.error("Socket timeout while receiving message")
            raise TimeoutError("Socket timeout while receiving message")
        except Exception as e:
            logger.error(f"Error receiving message: {str(e)}")
            raise ConnectionError(f"Failed to receive message: {str(e)}")
    
    def receive_exactly(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes of data"""
        if self.sock is None:
            raise ConnectionError("Socket is not connected")
            
        data: bytes = b''
        while len(data) < n:
            try:
                chunk: bytes = self.sock.recv(min(n - len(data), 4096))
                if not chunk:  # Connection closed
                    return None
                data += chunk
            except socket.timeout:
                logger.warning("Socket timeout while receiving data")
                raise TimeoutError("Socket timeout while receiving data")
            except socket.error as e:
                logger.error(f"Socket error while receiving data: {str(e)}")
                self.disconnect()
                raise ConnectionError(f"Socket error: {str(e)}")
        return data
    
    def set_timeout(self, timeout: int) -> None:
        """Set socket timeout"""
        if self.sock:
            self.sock.settimeout(timeout)

# -------------------------------------------------------------------
# Proxy for forwarding MCP requests to IDA Plugin
# -------------------------------------------------------------------

class IDAStdioProxy:
    """MCP Proxy that forwards requests from stdio to IDA plugin"""
    
    def __init__(self):
        self.transport = IDASocketTransport()
        self.request_count: int = 0
    
    def send_request(self, request_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to IDA plugin socket server and return response"""
        # Ensure connection is established
        if not self.transport.ensure_connection():
            return {"error": "Cannot connect to IDA plugin"}
        
        try:
            # Set appropriate timeout for potentially long operations
            if request_type in ["get_tool_list", "execute_script", "execute_script_from_file"]:
                self.transport.set_timeout(self.transport.long_timeout)
                logger.debug(f"Set timeout to {self.transport.long_timeout}s for possibly slow operation")
            else:
                self.transport.set_timeout(self.transport.default_timeout)

            # Create request with unique ID
            request_id: str = str(uuid.uuid4())
            self.request_count += 1
            request_count: int = self.request_count
        
            request: Dict[str, Any] = {
                "id": request_id,
                "count": request_count,
                "type": request_type,
                "data": data
            }
        
            logger.debug(f"Sending request: {request_id}, type: {request_type}, count: {request_count}")
        
            try:
                # Encode and send request
                request_json: str = json.dumps(request)
                # 验证JSON格式正确
                json.loads(request_json)  # 测试JSON是否有效
                
                self.transport.send_message(request_json.encode('utf-8'))
            
                # Receive and decode response
                response_data: bytes = self.transport.receive_message()
                response_str: str = response_data.decode('utf-8')
                
                # 尝试解析JSON之前检查格式
                if not response_str.strip():
                    logger.error("Received empty response")
                    return {"error": "Received empty response from IDA plugin"}
                
                # 检查JSON字符串是否有前缀/后缀
                if not response_str.strip().startswith('{'):
                    logger.error(f"Invalid JSON response format: {response_str[:50]}...")
                    # 尝试查找JSON的开始位置
                    start_pos = response_str.find('{')
                    if start_pos >= 0:
                        response_str = response_str[start_pos:]
                        logger.info(f"Attempted to fix JSON by removing prefix: {response_str[:50]}...")
                    else:
                        return {"error": "Response does not contain valid JSON"}
                
                # 尝试解析JSON
                try:
                    response: Dict[str, Any] = json.loads(response_str)
                except json.JSONDecodeError as e:
                    logger.error(f"JSON parse error: {str(e)}, response: {response_str[:200]}...")
                    return {"error": f"Invalid JSON response: {str(e)}"}
                
                # Verify response matches request
                response_id: str = response.get("id")
                if response_id != request_id:
                    logger.warning(f"Response ID mismatch! Request ID: {request_id}, Response ID: {response_id}")
                
                logger.debug(f"Received response for request {request_id}")
                return response
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON response: {str(e)}")
                return {"error": f"Invalid JSON response: {str(e)}"}
            except ConnectionError as e:
                logger.error(f"Connection error: {str(e)}")
                self.transport.disconnect()
                return {"error": f"Connection error: {str(e)}"}
            except TimeoutError as e:
                logger.error(f"Timeout error: {str(e)}")
                self.transport.disconnect()
                return {"error": f"Timeout error: {str(e)}"}
            except ResponseError as e:
                logger.error(f"Response error: {str(e)}")
                return {"error": f"Response error: {str(e)}"}
            except Exception as e:
                logger.error(f"Error communicating with IDA plugin: {str(e)}")
                self.transport.disconnect()
                return {"error": str(e)}
        finally:
            # Reset timeout to default
            self.transport.set_timeout(self.transport.default_timeout)

# -------------------------------------------------------------------
# Format responses from IDA plugin to MCP format
# -------------------------------------------------------------------

class ResponseFormatter:
    """Format responses from IDA plugin to MCP format"""
    
    @staticmethod
    def format_response(response: Dict[str, Any]) -> List[TextContent]:
        """Format a response from IDA plugin to MCP format"""
        # Check for errors
        if "error" in response:
            return [TextContent(
                type="text",
                text=f"Error: {response['error']}"
            )]
        
        # If response contains formatted_response, use it directly
        if "formatted_response" in response:
            return [TextContent(
                type="text",
                text=response["formatted_response"]
            )]
            
        # If response contains content_items, convert them to TextContent
        if "content_items" in response:
            return [TextContent(
                type="text",
                text=item
            ) for item in response["content_items"]]
            
        # Return raw response as JSON string if no recognizable format
        return [TextContent(
            type="text",
            text=json.dumps(response, indent=2)
        )]

# -------------------------------------------------------------------
# Main MCP Server Controller
# -------------------------------------------------------------------

class MCPServerController:
    """Main controller for MCP server"""
    
    def __init__(self):
        self.proxy = IDAStdioProxy()
    
    async def get_tool_list(self) -> List[Tool]:
        """Get list of tools from the IDA plugin"""
        try:
            response = self.proxy.send_request("get_tool_list", {})
            
            if "error" in response:
                logger.error(f"Error getting tool list: {response['error']}")
                return []
                
            if "tools" in response and isinstance(response["tools"], list):
                # 确保工具列表的格式正确
                tools = []
                for tool_data in response["tools"]:
                    # 确保每个工具都包含所需字段
                    if all(key in tool_data for key in ["name", "description", "inputSchema"]):
                        tools.append(Tool(
                            name=tool_data["name"],
                            description=tool_data["description"],
                            inputSchema=tool_data["inputSchema"]
                        ))
                    else:
                        logger.warning(f"Skipping tool with missing fields: {tool_data}")
                
                logger.info(f"Successfully retrieved {len(tools)} tools from plugin")
                return tools
                
            logger.error(f"Invalid response format for tool list: {response}")
            return []
        except Exception as e:
            logger.error(f"Error getting tool list: {str(e)}", exc_info=True)
            return []
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> List[TextContent]:
        """Call a tool with the given arguments"""
        # Ensure connection exists
        if not self.proxy.transport.connected and not self.proxy.transport.ensure_connection():
            return [TextContent(
                type="text",
                text=f"Error: Cannot connect to IDA plugin. Please ensure the plugin is running."
            )]
            
        try:
            # Forward request to plugin
            response = self.proxy.send_request("call_tool", {
                "tool_name": name,
                "arguments": arguments
            })
            
            # Format response
            return ResponseFormatter.format_response(response)
                
        except Exception as e:
            logger.error(f"Error calling tool: {str(e)}", exc_info=True)
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

# -------------------------------------------------------------------
# MCP Server Entry Point
# -------------------------------------------------------------------

async def serve() -> None:
    """MCP server main entry point"""
    try:
        # 避免在主流程中有输出，可能会干扰stdio通信
        logger.info("Starting IDA MCP Proxy Server")
        
        # 创建一个定向日志处理器，确保日志不写入到stdout
        file_handler = logging.FileHandler("mcp_ida_proxy.log")
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(file_handler)
        logger.removeHandler(logger.handlers[0])  # 移除stdout处理器
        
        # 创建MCP服务器
        server: Server = Server("mcp-ida")
        
        # 创建服务器控制器
        controller = MCPServerController()
        logger.info("MCP Server controller initialized")
    
        @server.list_tools()
        async def list_tools() -> List[Tool]:
            """Get list of tools from the IDA plugin"""
            tools = await controller.get_tool_list()
            logger.info(f"Providing list of {len(tools)} available tools")
            return tools
    
        @server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            """Forward tool calls to IDA plugin and handle responses"""
            logger.info(f"Calling tool: {name}")
            return await controller.call_tool(name, arguments)
    
        # 启动MCP服务器
        logger.info("Starting MCP Server with stdio transport")
        options = server.create_initialization_options()
        
        # 使用with语句确保资源正确释放
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, options, raise_exceptions=True)
            
    except Exception as e:
        # 错误记录到文件，避免写入stdout
        with open("mcp_ida_error.log", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - Fatal error: {str(e)}\n")
            import traceback
            traceback.print_exc(file=f)
