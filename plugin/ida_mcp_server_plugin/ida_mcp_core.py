import idaapi
import idautils
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_name
import ida_segment
import ida_lines
import idc
import json
import traceback
import functools
import queue
import re
import sys
import io
import builtins
import threading
import time
import resource
import platform
from typing import Any, Callable, TypeVar, Optional, Dict, List, Union, Tuple, Type, Set

# Attempt to import the ida_tool decorator
try:
    # This will be available when the plugin is loaded
    from ida_mcp_server_plugin import get_ida_tool_decorator
    ida_tool = get_ida_tool_decorator()
except ImportError:
    # Fallback for when the module is being loaded before the plugin
    def ida_tool(*args, **kwargs):
        def decorator(func):
            return func
        return decorator if args and callable(args[0]) else decorator

# Type variable for function return type
T = TypeVar('T')

class IDASyncError(Exception):
    """Exception raised for IDA synchronization errors"""
    pass

# Global call stack to track synchronization calls
call_stack: queue.LifoQueue[str] = queue.LifoQueue()

def sync_wrapper(func: Callable[..., T], sync_type: int) -> T:
    """
    Wrapper function to execute a function in IDA's main thread
    
    Args:
        func: The function to execute
        sync_type: Synchronization type (MFF_READ or MFF_WRITE)
        
    Returns:
        The result of the function execution
    """
    if sync_type not in [idaapi.MFF_READ, idaapi.MFF_WRITE]:
        error_str = f'Invalid sync type {sync_type} for function {func.__name__}'
        print(error_str)
        raise IDASyncError(error_str)
    
    # Container for the result
    result_container: queue.Queue[Any] = queue.Queue()
    
    def execute_in_main_thread() -> int:
        # Check if we're already inside a sync_wrapper call
        if not call_stack.empty():
            last_func = call_stack.get()
            error_str = f'Nested sync call detected: function {func.__name__} called from {last_func}'
            print(error_str)
            call_stack.put(last_func)  # Put it back
            raise IDASyncError(error_str)
        
        # Add function to call stack
        call_stack.put(func.__name__)
        
        try:
            # Execute function and store result
            result_container.put(func())
        except Exception as e:
            print(f"Error in {func.__name__}: {str(e)}")
            traceback.print_exc()
            result_container.put(None)
        finally:
            # Always remove function from call stack
            call_stack.get()
        
        return 1  # Required by execute_sync
    
    # Execute in IDA's main thread
    idaapi.execute_sync(execute_in_main_thread, sync_type)
    
    # Return the result
    return result_container.get()

def idaread(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator for functions that read from the IDA database
    
    Args:
        func: The function to decorate
        
    Returns:
        Decorated function that executes in IDA's main thread with read access
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        # Create a partial function with the arguments
        partial_func = functools.partial(func, *args, **kwargs)
        # Preserve the original function name
        partial_func.__name__ = func.__name__
        # Execute with sync_wrapper
        return sync_wrapper(partial_func, idaapi.MFF_READ)
    
    return wrapper

def idawrite(func: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator for functions that write to the IDA database
    
    Args:
        func: The function to decorate
        
    Returns:
        Decorated function that executes in IDA's main thread with write access
    """
    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        # Create a partial function with the arguments
        partial_func = functools.partial(func, *args, **kwargs)
        # Preserve the original function name
        partial_func.__name__ = func.__name__
        # Execute with sync_wrapper
        return sync_wrapper(partial_func, idaapi.MFF_WRITE)
    
    return wrapper

class IDAMCPCore:
    """Core functionality implementation class for IDA MCP"""
    
    def __init__(self):
        """Initialize core"""
        pass
    
    @idaread
    @ida_tool(description="获取当前二进制文件中的所有字符串")
    def get_all_strings(self, max_count: int = 1000, min_length: int = 4) -> Dict[str, Any]:
        """
        获取当前二进制文件中的所有字符串
        
        Args:
            max_count: 最大返回字符串数量
            min_length: 最小字符串长度
            
        Returns:
            包含所有字符串的结果字典
        """
        try:
            strings = []
            count = 0
            
            for s in idautils.Strings():
                if count >= max_count:
                    break
                
                if s and s.length >= min_length:
                    string_value = str(s)
                    address = s.ea
                    
                    strings.append({
                        "address": hex(address),
                        "value": string_value,
                        "length": s.length
                    })
                    count += 1
            
            return {
                "success": True,
                "strings": strings,
                "count": len(strings),
                "formatted_response": f"找到 {len(strings)} 个字符串"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"获取字符串时出错: {str(e)}",
                "formatted_response": f"获取字符串失败: {str(e)}"
            }

    @idaread
    def get_function_assembly_by_name(self, function_name: str) -> Dict[str, Any]:
        """Get assembly code for a function by its name"""
        try:
            # Get function address from name
            func = idaapi.get_func(idaapi.get_name_ea(0, function_name))
            if not func:
                return {"error": f"Function '{function_name}' not found"}
            
            # Call address-based implementation
            result = self._get_function_assembly_by_address_internal(func.start_ea)
            
            # If successful, add function name to result
            if "error" not in result:
                result["function_name"] = function_name
                
            return result
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_function_assembly_by_address(self, address: int) -> Dict[str, Any]:
        """Get assembly code for a function by its address"""
        return self._get_function_assembly_by_address_internal(address)
        
    def _get_function_assembly_by_address_internal(self, address: int) -> Dict[str, Any]:
        """Internal implementation for get_function_assembly_by_address without sync wrapper"""
        try:
            # Get function object
            func = ida_funcs.get_func(address)
            if not func:
                return {"error": f"Invalid function at {hex(address)}"}
            
            # Collect all assembly instructions
            assembly_lines = []
            for instr_addr in idautils.FuncItems(address):
                disasm = idc.GetDisasm(instr_addr)
                assembly_lines.append(f"{hex(instr_addr)}: {disasm}")
            
            if not assembly_lines:
                return {"error": "No assembly instructions found"}
                
            return {"assembly": "\n".join(assembly_lines)}
        except Exception as e:
            print(f"Error getting function assembly: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}


    @idaread
    def get_function_decompiled_by_name(self, function_name: str) -> Dict[str, Any]:
        """Get decompiled code for a function by its name"""
        try:
            # Get function address from name
            func_addr = idaapi.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"error": f"Function '{function_name}' not found"}
            
            # Call internal implementation without decorator
            result = self._get_function_decompiled_by_address_internal(func_addr)
            
            # If successful, add function name to result
            if "error" not in result:
                result["function_name"] = function_name
                
            return result
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_function_decompiled_by_address(self, address: int) -> Dict[str, Any]:
        """Get decompiled code for a function by its address"""
        return self._get_function_decompiled_by_address_internal(address)
    
    def _get_function_decompiled_by_address_internal(self, address: int) -> Dict[str, Any]:
        """Internal implementation for get_function_decompiled_by_address without sync wrapper"""
        try:
            # Get function from address
            func = idaapi.get_func(address)
            if not func:
                return {"error": f"No function found at address 0x{address:X}"}
            
            # Get function name
            func_name = idaapi.get_func_name(func.start_ea)
            
            # Try to import decompiler module
            try:
                import ida_hexrays
            except ImportError:
                return {"error": "Hex-Rays decompiler is not available"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "Unable to initialize Hex-Rays decompiler"}
            
            # Get decompiled function
            cfunc = None
            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
            except Exception as e:
                return {"error": f"Unable to decompile function: {str(e)}"}
            
            if not cfunc:
                return {"error": "Decompilation failed"}
            
            # Get pseudocode as string
            decompiled_code = str(cfunc)
            
            return {"decompiled_code": decompiled_code, "function_name": func_name}
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_current_function_assembly(self) -> Dict[str, Any]:
        """Get assembly code for the function at the current cursor position"""
        try:
            # Get current address
            curr_addr = idaapi.get_screen_ea()
            if curr_addr == idaapi.BADADDR:
                return {"error": "No valid cursor position"}
            
            # Use the internal implementation without decorator
            return self._get_function_assembly_by_address_internal(curr_addr)
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}

    @idaread
    def get_current_function_decompiled(self) -> Dict[str, Any]:
        """Get decompiled code for the function at the current cursor position"""
        try:
            # Get current address
            curr_addr = idaapi.get_screen_ea()
            if curr_addr == idaapi.BADADDR:
                return {"error": "No valid cursor position"}
            
            # Use the internal implementation without decorator
            return self._get_function_decompiled_by_address_internal(curr_addr)
        except Exception as e:
            traceback.print_exc()
            return {"error": str(e)}
    
    @idaread
    def get_global_variable_by_name(self, variable_name: str) -> Dict[str, Any]:
        """Get global variable information by its name"""
        try:
            # Get variable address
            var_addr: int = ida_name.get_name_ea(0, variable_name)
            if var_addr == idaapi.BADADDR:
                return {"error": f"Global variable '{variable_name}' not found"}
            
            # Call internal implementation
            result = self._get_global_variable_by_address_internal(var_addr)
            
            # If successful, add variable name to result
            if "error" not in result and "variable_info" in result:
                # Parse the JSON string back to dict to modify it
                var_info = json.loads(result["variable_info"])
                var_info["name"] = variable_name
                # Convert back to JSON string
                result["variable_info"] = json.dumps(var_info, indent=2)
                
            return result
        except Exception as e:
            print(f"Error getting global variable by name: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    @idaread
    def get_global_variable_by_address(self, address: int) -> Dict[str, Any]:
        """Get global variable information by its address"""
        return self._get_global_variable_by_address_internal(address)
    
    def _get_global_variable_by_address_internal(self, address: int) -> Dict[str, Any]:
        """Internal implementation for get_global_variable_by_address without sync wrapper"""
        try:
            # Verify address is valid
            if address == idaapi.BADADDR:
                return {"error": f"Invalid address: {hex(address)}"}
            
            # Get variable name if available
            variable_name = ida_name.get_name(address)
            if not variable_name:
                variable_name = f"unnamed_{hex(address)}"
            
            # Get variable segment
            segment: Optional[ida_segment.segment_t] = ida_segment.getseg(address)
            if not segment:
                return {"error": f"No segment found for address {hex(address)}"}
            
            segment_name: str = ida_segment.get_segm_name(segment)
            segment_class: str = ida_segment.get_segm_class(segment)
            
            # Get variable type
            tinfo = idaapi.tinfo_t()
            guess_type: bool = idaapi.guess_tinfo(tinfo, address)
            type_str: str = tinfo.get_type_name() if guess_type else "unknown"
            
            # Try to get variable value
            size: int = ida_bytes.get_item_size(address)
            if size <= 0:
                size = 8  # Default to 8 bytes
            
            # Read data based on size
            value: Optional[int] = None
            if size == 1:
                value = ida_bytes.get_byte(address)
            elif size == 2:
                value = ida_bytes.get_word(address)
            elif size == 4:
                value = ida_bytes.get_dword(address)
            elif size == 8:
                value = ida_bytes.get_qword(address)
            
            # Build variable info
            var_info: Dict[str, Any] = {
                "name": variable_name,
                "address": hex(address),
                "segment": segment_name,
                "segment_class": segment_class,
                "type": type_str,
                "size": size,
                "value": hex(value) if value is not None else "N/A"
            }
            
            # If it's a string, try to read string content
            if ida_bytes.is_strlit(ida_bytes.get_flags(address)):
                str_value = idc.get_strlit_contents(address, -1, 0)
                if str_value:
                    try:
                        var_info["string_value"] = str_value.decode('utf-8', errors='replace')
                    except:
                        var_info["string_value"] = str(str_value)
            
            return {"variable_info": json.dumps(var_info, indent=2)}
        except Exception as e:
            print(f"Error getting global variable by address: {str(e)}")
            traceback.print_exc()
            return {"error": str(e)}
    
    @idawrite
    def rename_global_variable(self, old_name: str, new_name: str) -> Dict[str, Any]:
        """Rename a global variable"""
        return self._rename_global_variable_internal(old_name, new_name)
        
    def _rename_global_variable_internal(self, old_name: str, new_name: str) -> Dict[str, Any]:
        """Internal implementation for rename_global_variable without sync wrapper"""
        try:
            # Get variable address
            var_addr: int = ida_name.get_name_ea(0, old_name)
            if var_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Variable '{old_name}' not found"}
            
            # Check if new name is already in use
            if ida_name.get_name_ea(0, new_name) != idaapi.BADADDR:
                return {"success": False, "message": f"Name '{new_name}' is already in use"}
            
            # Try to rename
            if not ida_name.set_name(var_addr, new_name):
                return {"success": False, "message": f"Failed to rename variable, possibly due to invalid name format or other IDA restrictions"}
            
            # Refresh view
            self._refresh_view_internal()
            
            return {"success": True, "message": f"Variable renamed from '{old_name}' to '{new_name}' at address {hex(var_addr)}"}
        
        except Exception as e:
            print(f"Error renaming variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def rename_function(self, old_name: str, new_name: str) -> Dict[str, Any]:
        """Rename a function"""
        return self._rename_function_internal(old_name, new_name)
        
    def _rename_function_internal(self, old_name: str, new_name: str) -> Dict[str, Any]:
        """Internal implementation for rename_function without sync wrapper"""
        try:
            # Get function address
            func_addr: int = ida_name.get_name_ea(0, old_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{old_name}' not found"}
            
            # Check if it's a function
            func: Optional[ida_funcs.func_t] = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{old_name}' is not a function"}
            
            # Check if new name is already in use
            if ida_name.get_name_ea(0, new_name) != idaapi.BADADDR:
                return {"success": False, "message": f"Name '{new_name}' is already in use"}
            
            # Try to rename
            if not ida_name.set_name(func_addr, new_name):
                return {"success": False, "message": f"Failed to rename function, possibly due to invalid name format or other IDA restrictions"}
            
            # Refresh view
            self._refresh_view_internal()
            
            return {"success": True, "message": f"Function renamed from '{old_name}' to '{new_name}' at address {hex(func_addr)}"}
        
        except Exception as e:
            print(f"Error renaming function: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    
    @idawrite
    def rename_local_variable(self, function_name: str, old_name: str, new_name: str) -> Dict[str, Any]:
        """Rename a local variable within a function"""
        return self._rename_local_variable_internal(function_name, old_name, new_name)
        
    def _rename_local_variable_internal(self, function_name: str, old_name: str, new_name: str) -> Dict[str, Any]:
        """Internal implementation for rename_local_variable without sync wrapper"""
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not old_name:
                return {"success": False, "message": "Old variable name cannot be empty"}
            if not new_name:
                return {"success": False, "message": "New variable name cannot be empty"}
            
            # Get function address
            func_addr: int = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func: Optional[ida_funcs.func_t] = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"success": False, "message": "Hex-Rays decompiler is not available"}
            
            # Get decompilation result
            cfunc: Optional[ida_hexrays.cfunc_t] = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"success": False, "message": f"Failed to decompile function '{function_name}'"}
            
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Find local variable to rename
            found: bool = False
            renamed: bool = False
            lvar: Optional[ida_hexrays.lvar_t] = None
            
            # Iterate through all local variables
            lvars = cfunc.get_lvars()
            for i in range(lvars.size()):
                v = lvars[i]
                if v.name == old_name:
                    lvar = v
                    found = True
                    break
            
            if not found:
                return {"success": False, "message": f"Local variable '{old_name}' not found in function '{function_name}'"}
            
            # Rename local variable
            if ida_hexrays.rename_lvar(cfunc.entry_ea, lvar.name, new_name):
                renamed = True
            
            if renamed:
                # Refresh view
                self._refresh_view_internal()
                return {"success": True, "message": f"Local variable renamed from '{old_name}' to '{new_name}' in function '{function_name}'"}
            else:
                return {"success": False, "message": f"Failed to rename local variable from '{old_name}' to '{new_name}', possibly due to invalid name format or other IDA restrictions"}
        
        except Exception as e:
            print(f"Error renaming local variable: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    
    @idawrite
    def add_assembly_comment(self, address: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Add an assembly comment"""
        return self._add_assembly_comment_internal(address, comment, is_repeatable)
        
    def _add_assembly_comment_internal(self, address: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Internal implementation for add_assembly_comment without sync wrapper"""
        try:
            # Convert address string to integer
            addr: int
            if isinstance(address, str):
                if address.startswith("0x"):
                    addr = int(address, 16)
                else:
                    try:
                        addr = int(address, 16)  # Try parsing as hex
                    except ValueError:
                        try:
                            addr = int(address)  # Try parsing as decimal
                        except ValueError:
                            return {"success": False, "message": f"Invalid address format: {address}"}
            else:
                addr = address
            
            # Check if address is valid
            if addr == idaapi.BADADDR or not ida_bytes.is_loaded(addr):
                return {"success": False, "message": f"Invalid or unloaded address: {hex(addr)}"}
            
            # Add comment
            result: bool = idc.set_cmt(addr, comment, is_repeatable)
            if result:
                # Refresh view
                self._refresh_view_internal()
                comment_type: str = "repeatable" if is_repeatable else "regular"
                return {"success": True, "message": f"Added {comment_type} assembly comment at address {hex(addr)}"}
            else:
                return {"success": False, "message": f"Failed to add assembly comment at address {hex(addr)}"}
        
        except Exception as e:
            print(f"Error adding assembly comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def rename_multi_local_variables(self, function_name: str, rename_pairs_old2new: List[Dict[str, str]]) -> Dict[str, Any]:
        """Rename multiple local variables within a function at once"""
        try:
            success_count: int = 0
            failed_pairs: List[Dict[str, str]] = []
    
            for pair in rename_pairs_old2new:
                old_name = next(iter(pair.keys()))
                new_name = pair[old_name]
                
                # Call existing rename_local_variable_internal for each pair
                result = self._rename_local_variable_internal(function_name, old_name, new_name)
                
                if result.get("success", False):
                    success_count += 1
                else:
                    failed_pairs.append({
                        "old_name": old_name,
                        "new_name": new_name,
                        "error": result.get("message", "Unknown error")
                    })
    
            return {
                "success": True,
                "message": f"Renamed {success_count} out of {len(rename_pairs_old2new)} local variables",
                "success_count": success_count,
                "failed_pairs": failed_pairs
            }
    
        except Exception as e:
            print(f"Error in rename_multi_local_variables: {str(e)}")
            traceback.print_exc()
            return {
                "success": False,
                "message": str(e),
                "success_count": 0,
                "failed_pairs": rename_pairs_old2new
            }
    
    @idawrite
    def rename_multi_global_variables(self, rename_pairs_old2new: List[Dict[str, str]]) -> Dict[str, Any]:
        """Rename multiple global variables at once"""
        try:
            success_count: int = 0
            failed_pairs: List[Dict[str, str]] = []
    
            for pair in rename_pairs_old2new:
                old_name = next(iter(pair.keys()))
                new_name = pair[old_name]
                
                # Call existing rename_global_variable_internal for each pair
                result = self._rename_global_variable_internal(old_name, new_name)
                
                if result.get("success", False):
                    success_count += 1
                else:
                    failed_pairs.append({
                        "old_name": old_name,
                        "new_name": new_name,
                        "error": result.get("message", "Unknown error")
                    })
    
            return {
                "success": True,
                "message": f"Renamed {success_count} out of {len(rename_pairs_old2new)} global variables",
                "success_count": success_count,
                "failed_pairs": failed_pairs
            }
    
        except Exception as e:
            print(f"Error in rename_multi_global_variables: {str(e)}")
            traceback.print_exc()
            return {
                "success": False,
                "message": str(e),
                "success_count": 0,
                "failed_pairs": rename_pairs_old2new
            }
    
    @idawrite
    def rename_multi_functions(self, rename_pairs_old2new: List[Dict[str, str]]) -> Dict[str, Any]:
        """Rename multiple functions at once"""
        try:
            success_count: int = 0
            failed_pairs: List[Dict[str, str]] = []
    
            for pair in rename_pairs_old2new:
                old_name = next(iter(pair.keys()))
                new_name = pair[old_name]
                
                # Call existing rename_function_internal for each pair
                result = self._rename_function_internal(old_name, new_name)
                
                if result.get("success", False):
                    success_count += 1
                else:
                    failed_pairs.append({
                        "old_name": old_name,
                        "new_name": new_name,
                        "error": result.get("message", "Unknown error")
                    })
    
            return {
                "success": True,
                "message": f"Renamed {success_count} out of {len(rename_pairs_old2new)} functions",
                "success_count": success_count,
                "failed_pairs": failed_pairs
            }
    
        except Exception as e:
            print(f"Error in rename_multi_functions: {str(e)}")
            traceback.print_exc()
            return {
                "success": False,
                "message": str(e),
                "success_count": 0,
                "failed_pairs": rename_pairs_old2new
            }
    
    @idawrite
    def add_function_comment(self, function_name: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Add a comment to a function"""
        return self._add_function_comment_internal(function_name, comment, is_repeatable)
        
    def _add_function_comment_internal(self, function_name: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Internal implementation for add_function_comment without sync wrapper"""
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not comment:
                # Allow empty comment to clear the comment
                comment = ""
            
            # Get function address
            func_addr: int = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func: Optional[ida_funcs.func_t] = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Open pseudocode view
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Add function comment
            # is_repeatable=True means show comment at all references to this function
            # is_repeatable=False means show comment only at function definition
            result: bool = idc.set_func_cmt(func_addr, comment, is_repeatable)
            
            if result:
                # Refresh view
                self._refresh_view_internal()
                comment_type: str = "repeatable" if is_repeatable else "regular"
                return {"success": True, "message": f"Added {comment_type} comment to function '{function_name}'"}
            else:
                return {"success": False, "message": f"Failed to add comment to function '{function_name}'"}
        
        except Exception as e:
            print(f"Error adding function comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def add_pseudocode_comment(self, function_name: str, address: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Add a comment to a specific address in the function's decompiled pseudocode"""
        return self._add_pseudocode_comment_internal(function_name, address, comment, is_repeatable)
        
    def _add_pseudocode_comment_internal(self, function_name: str, address: str, comment: str, is_repeatable: bool) -> Dict[str, Any]:
        """Internal implementation for add_pseudocode_comment without sync wrapper"""
        try:
            # Parameter validation
            if not function_name:
                return {"success": False, "message": "Function name cannot be empty"}
            if not address:
                return {"success": False, "message": "Address cannot be empty"}
            if not comment:
                # Allow empty comment to clear the comment
                comment = ""
            
            # Get function address
            func_addr: int = ida_name.get_name_ea(0, function_name)
            if func_addr == idaapi.BADADDR:
                return {"success": False, "message": f"Function '{function_name}' not found"}
            
            # Check if it's a function
            func: Optional[ida_funcs.func_t] = ida_funcs.get_func(func_addr)
            if not func:
                return {"success": False, "message": f"'{function_name}' is not a function"}
            
            # Check if decompiler is available
            if not ida_hexrays.init_hexrays_plugin():
                return {"success": False, "message": "Hex-Rays decompiler is not available"}
            
            # Get decompilation result
            cfunc: Optional[ida_hexrays.cfunc_t] = ida_hexrays.decompile(func_addr)
            if not cfunc:
                return {"success": False, "message": f"Failed to decompile function '{function_name}'"}
            
            # Open pseudocode view
            ida_hexrays.open_pseudocode(func_addr, 0)
            
            # Convert address string to integer
            addr: int
            if isinstance(address, str):
                if address.startswith("0x"):
                    addr = int(address, 16)
                else:
                    try:
                        addr = int(address, 16)  # Try parsing as hex
                    except ValueError:
                        try:
                            addr = int(address)  # Try parsing as decimal
                        except ValueError:
                            return {"success": False, "message": f"Invalid address format: {address}"}
            else:
                addr = address
                
            # Check if address is valid
            if addr == idaapi.BADADDR or not ida_bytes.is_loaded(addr):
                return {"success": False, "message": f"Invalid or unloaded address: {hex(addr)}"}
                
            # Check if address is within function
            if not (func.start_ea <= addr < func.end_ea):
                return {"success": False, "message": f"Address {hex(addr)} is not within function '{function_name}'"}
            
            # Create treeloc_t object for comment location
            loc = ida_hexrays.treeloc_t()
            loc.ea = addr
            loc.itp = ida_hexrays.ITP_BLOCK1  # Comment location
            
            # Set comment
            cfunc.set_user_cmt(loc, comment)
            cfunc.save_user_cmts()
            
            # Refresh view
            self._refresh_view_internal()
            
            comment_type: str = "repeatable" if is_repeatable else "regular"
            return {
                "success": True, 
                "message": f"Added {comment_type} comment at address {hex(addr)} in function '{function_name}'"
            }    
        
        except Exception as e:
            print(f"Error adding pseudocode comment: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}
    
    @idawrite
    def refresh_view(self) -> Dict[str, Any]:
        """Refresh IDA Pro view"""
        return self._refresh_view_internal()
    
    def _refresh_view_internal(self) -> Dict[str, Any]:
        """Implementation of refreshing view in IDA main thread"""
        try:
            # Refresh disassembly view
            idaapi.refresh_idaview_anyway()
            
            # Refresh decompilation view
            current_widget = idaapi.get_current_widget()
            if current_widget:
                widget_type: int = idaapi.get_widget_type(current_widget)
                if widget_type == idaapi.BWN_PSEUDOCODE:
                    # If current view is pseudocode, refresh it
                    vu = idaapi.get_widget_vdui(current_widget)
                    if vu:
                        vu.refresh_view(True)
            
            # Try to find and refresh all open pseudocode windows
            for i in range(5):  # Check multiple possible pseudocode windows
                widget_name: str = f"Pseudocode-{chr(65+i)}"  # Pseudocode-A, Pseudocode-B, ...
                widget = idaapi.find_widget(widget_name)
                if widget:
                    vu = idaapi.get_widget_vdui(widget)
                    if vu:
                        vu.refresh_view(True)
            
            return {"success": True, "message": "Views refreshed successfully"}
        except Exception as e:
            print(f"Error refreshing views: {str(e)}")
            traceback.print_exc()
            return {"success": False, "message": str(e)}

    @idawrite
    def execute_script(self, script: str) -> Dict[str, Any]:
        """Execute a Python script in IDA context"""
        return self._execute_script_internal(script)
        
    def _execute_script_internal(self, script: str) -> Dict[str, Any]:
        """Internal implementation for execute_script without sync wrapper"""
        try:
            print(f"Executing script, length: {len(script) if script else 0}")
            
            # Check for empty script
            if not script or not script.strip():
                print("Error: Empty script provided")
                return {
                    "success": False,
                    "error": "Empty script provided",
                    "stdout": "",
                    "stderr": "",
                    "traceback": ""
                }
            
            # Run script through safety check first
            is_safe, safety_message = ScriptSandbox.check_code_safety(script)
            if not is_safe:
                print(f"Script safety check failed: {safety_message}")
                return {
                    "success": False,
                    "error": f"Script safety check failed: {safety_message}",
                    "stdout": "",
                    "stderr": f"Security violation: {safety_message}",
                    "traceback": ""
                }
                
            # Create a sandboxed namespace for script execution
            script_globals = ScriptSandbox.create_safe_globals()
            script_locals = {}

            # Save original stdin/stdout/stderr
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            original_stdin = sys.stdin

            # Create string IO objects to capture output
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            
            # Redirect stdout/stderr to capture output
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            
            # Prevent script from trying to read from stdin
            sys.stdin = io.StringIO()

            try:
                # Create UI hooks 
                print("Setting up UI hooks")
                hooks = self._create_ui_hooks()
                hooks.hook()

                # Install auto-continue handlers for common dialogs - but first, redirect stderr
                temp_stderr = sys.stderr
                auto_handler_stderr = io.StringIO()
                sys.stderr = auto_handler_stderr
                
                print("Installing auto handlers")
                self._install_auto_handlers()
                
                # Restore stderr and save auto-handler errors separately
                sys.stderr = stderr_capture
                auto_handler_errors = auto_handler_stderr.getvalue()
                
                # Only log auto-handler errors, don't include in script output
                if auto_handler_errors:
                    print(f"Auto-handler setup errors (not shown to user): {auto_handler_errors}")

                # Execute the script in sandbox with timeout protection
                print("Executing script in sandbox...")
                
                # Set script execution timeout (in seconds)
                SCRIPT_TIMEOUT = 30
                
                # Flag to track script timeout
                script_timed_out = False
                
                # Reset resource monitor
                ResourceMonitor.reset()
                
                # Start resource monitoring thread
                resource_thread = threading.Thread(target=ResourceMonitor.monitor_resources)
                resource_thread.daemon = True
                resource_thread.start()
                
                # Result container for thread
                thread_result = {"error": None, "traceback": None}
                
                # Define function to execute script in a separate thread
                def execute_script_thread():
                    try:
                        exec(script, script_globals, script_locals)
                    except Exception as e:
                        import traceback as tb_module
                        thread_result["error"] = str(e)
                        thread_result["traceback"] = tb_module.format_exc()
                
                # Create and start thread
                script_thread = threading.Thread(target=execute_script_thread)
                script_thread.daemon = True  # Allow thread to be killed when main thread exits
                script_thread.start()
                
                # Wait for thread to complete with timeout
                script_thread.join(SCRIPT_TIMEOUT)
                
                # Check if resource limits were exceeded
                if ResourceMonitor.resource_exceeded:
                    script_timed_out = True
                    stderr_capture.write(f"\n{ResourceMonitor.error_message}")
                    print(f"Resource limit exceeded: {ResourceMonitor.error_message}")
                # Check if thread is still running (timeout occurred)
                elif script_thread.is_alive():
                    script_timed_out = True
                    stderr_capture.write(f"\nScript execution timed out after {SCRIPT_TIMEOUT} seconds. This could be due to an infinite loop or a very long-running operation.")
                    print(f"Script execution timed out after {SCRIPT_TIMEOUT} seconds")
                    # Note: We can't forcibly terminate the thread in Python, but setting daemon=True
                    # ensures it will be terminated when the main thread exits
                else:
                    print("Script execution completed")
                
                # If thread had an error, propagate it
                if thread_result["error"]:
                    raise Exception(thread_result["error"])
                
                # Get captured output
                stdout = stdout_capture.getvalue()
                stderr = stderr_capture.getvalue()
                
                # Filter out auto-handler messages from stdout
                stdout_lines = stdout.splitlines()
                filtered_stdout_lines = []
                
                for line in stdout_lines:
                    skip_line = False
                    auto_handler_messages = [
                        "Setting up UI hooks",
                        "Installing auto handlers",
                        "Error installing auto handlers",
                        "Found and saved",
                        "Could not access user_cancelled",
                        "Installed auto_",
                        "Auto handlers installed",
                        "Note: Could not",
                        "Restoring IO streams",
                        "Unhooking UI hooks",
                        "Restoring original handlers",
                        "Refreshing view",
                        "Original handlers restored",
                        "No original handlers"
                    ]
                    
                    for msg in auto_handler_messages:
                        if msg in line:
                            skip_line = True
                            break
                            
                    if not skip_line:
                        filtered_stdout_lines.append(line)
                
                filtered_stdout = "\n".join(filtered_stdout_lines)
                
                # Compile script results - ensure all fields are present
                result = {
                    "stdout": filtered_stdout.strip() if filtered_stdout else "",
                    "stderr": stderr.strip() if stderr else "",
                    "success": not script_timed_out,
                    "traceback": "",
                    "timed_out": script_timed_out
                }
                
                # Add timeout/resource information if script timed out
                if script_timed_out:
                    if ResourceMonitor.resource_exceeded:
                        result["error"] = ResourceMonitor.error_message
                    else:
                        result["error"] = f"Script execution timed out after {SCRIPT_TIMEOUT} seconds"
                
                # Check for return value (only if script didn't time out)
                if not script_timed_out and "result" in script_locals:
                    try:
                        print(f"Script returned value of type: {type(script_locals['result']).__name__}")
                        result["return_value"] = str(script_locals["result"])
                    except Exception as rv_err:
                        print(f"Error converting return value: {str(rv_err)}")
                        result["stderr"] += f"\nError converting return value: {str(rv_err)}"
                        result["return_value"] = "Error: Could not convert return value to string"
                
                print(f"Returning script result with keys: {', '.join(result.keys())}")
                return result
            except Exception as e:
                import traceback as tb_module
                error_msg = str(e)
                tb = tb_module.format_exc()
                print(f"Script execution error: {error_msg}")
                print(tb)
                return {
                    "success": False,
                    "stdout": stdout_capture.getvalue().strip() if stdout_capture else "",
                    "stderr": stderr_capture.getvalue().strip() if stderr_capture else "",
                    "error": error_msg,
                    "traceback": tb
                }
            finally:
                # Restore original stdin/stdout/stderr
                print("Restoring IO streams")
                sys.stdout = original_stdout
                sys.stderr = original_stderr
                sys.stdin = original_stdin
                
                # Unhook UI hooks
                print("Unhooking UI hooks")
                hooks.unhook()
                
                # Restore original handlers
                print("Restoring original handlers")
                self._restore_original_handlers()
                
                # Refresh view to show any changes made by script
                print("Refreshing view")
                self._refresh_view_internal()
        except Exception as e:
            print(f"Error in execute_script outer scope: {str(e)}")
            traceback.print_exc()
            return {
                "success": False,
                "stdout": "",
                "stderr": "",
                "error": str(e),
                "traceback": traceback.format_exc()
            }

    @idawrite
    def execute_script_from_file(self, file_path: str) -> Dict[str, Any]:
        """Execute a Python script from a file in IDA context"""
        return self._execute_script_from_file_internal(file_path)
        
    def _execute_script_from_file_internal(self, file_path: str) -> Dict[str, Any]:
        """Internal implementation for execute_script_from_file without sync wrapper"""
        try:
            # Check if file path is provided
            if not file_path or not file_path.strip():
                return {
                    "success": False,
                    "error": "No file path provided",
                    "stdout": "",
                    "stderr": "",
                    "traceback": ""
                }
                
            # Check if file exists
            import os
            if not os.path.exists(file_path):
                return {
                    "success": False,
                    "error": f"Script file not found: {file_path}",
                    "stdout": "",
                    "stderr": "",
                    "traceback": ""
                }
            
            try:
                # Read script content
                with open(file_path, 'r') as f:
                    script = f.read()
                
                # Execute script using internal method
                return self._execute_script_internal(script)
            except Exception as file_error:
                print(f"Error reading or executing script file: {str(file_error)}")
                traceback.print_exc()
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": "",
                    "error": f"Error with script file: {str(file_error)}",
                    "traceback": traceback.format_exc()
                }
        except Exception as e:
            print(f"Error executing script from file: {str(e)}")
            traceback.print_exc()
            return {
                "success": False,
                "stdout": "",
                "stderr": "",
                "error": str(e),
                "traceback": traceback.format_exc()
            }

    def _create_ui_hooks(self) -> idaapi.UI_Hooks:
        """Create UI hooks to suppress dialogs during script execution"""
        try:
            class DialogHook(idaapi.UI_Hooks):
                def populating_widget_popup(self, widget, popup):
                    # Just suppress all popups
                    return 1
                
                def finish_populating_widget_popup(self, widget, popup):
                    # Also suppress here
                    return 1
                
                def ready_to_run(self):
                    # Always continue
                    return 1
                
                def updating_actions(self, ctx):
                    # Always continue
                    return 1
                
                def updated_actions(self):
                    # Always continue
                    return 1
                
                def ui_refresh(self, cnd):
                    # Suppress UI refreshes
                    return 1
            
            hooks = DialogHook()
            return hooks
        except Exception as e:
            print(f"Error creating UI hooks: {str(e)}")
            traceback.print_exc()
            
            # Create minimal dummy hooks that won't cause errors
            class DummyHook:
                def hook(self):
                    print("Using dummy hook (hook)")
                    pass
                
                def unhook(self):
                    print("Using dummy hook (unhook)")
                    pass
            
            return DummyHook()

    def _install_auto_handlers(self) -> None:
        """Install auto-continue handlers for common dialogs"""
        try:
            import ida_kernwin
            
            # Save original handlers - with safer access to cvar.user_cancelled
            self._original_handlers = {}
            
            # Try to access user_cancelled more safely
            try:
                if hasattr(ida_kernwin, 'cvar') and hasattr(ida_kernwin.cvar, 'user_cancelled'):
                    self._original_handlers["yn"] = ida_kernwin.cvar.user_cancelled
                    print("Found and saved user_cancelled handler")
            except Exception as yn_err:
                print(f"Note: Could not access user_cancelled: {str(yn_err)}")
            
            # Save other dialog handlers
            if hasattr(ida_kernwin, 'ask_buttons'):
                self._original_handlers["buttons"] = ida_kernwin.ask_buttons
            
            if hasattr(ida_kernwin, 'ask_text'):
                self._original_handlers["text"] = ida_kernwin.ask_text
            
            if hasattr(ida_kernwin, 'ask_file'):
                self._original_handlers["file"] = ida_kernwin.ask_file
            
            # Define auto handlers
            def auto_yes_no(*args, **kwargs):
                return 1  # Return "Yes"
            
            def auto_buttons(*args, **kwargs):
                return 1  # Return first button
            
            def auto_text(*args, **kwargs):
                return ""  # Return empty text
            
            def auto_file(*args, **kwargs):
                return ""  # Return empty filename
            
            # Install auto handlers only for what we successfully saved
            if "yn" in self._original_handlers:
                try:
                    ida_kernwin.cvar.user_cancelled = auto_yes_no
                    print("Installed auto_yes_no handler")
                except Exception as e:
                    print(f"Could not install auto_yes_no handler: {str(e)}")
            
            if "buttons" in self._original_handlers:
                ida_kernwin.ask_buttons = auto_buttons
                print("Installed auto_buttons handler")
            
            if "text" in self._original_handlers:
                ida_kernwin.ask_text = auto_text
                print("Installed auto_text handler")
            
            if "file" in self._original_handlers:
                ida_kernwin.ask_file = auto_file
                print("Installed auto_file handler")
            
            print(f"Auto handlers installed successfully. Installed handlers: {', '.join(self._original_handlers.keys())}")
        except Exception as e:
            print(f"Error installing auto handlers: {str(e)}")
            traceback.print_exc()
            # Ensure _original_handlers exists even on failure
            if not hasattr(self, "_original_handlers"):
                self._original_handlers = {}

    def _restore_original_handlers(self) -> None:
        """Restore original dialog handlers"""
        try:
            if hasattr(self, "_original_handlers"):
                import ida_kernwin
                
                # Restore original handlers (only what was successfully saved)
                if "yn" in self._original_handlers:
                    try:
                        ida_kernwin.cvar.user_cancelled = self._original_handlers["yn"]
                        print("Restored user_cancelled handler")
                    except Exception as e:
                        print(f"Could not restore user_cancelled handler: {str(e)}")
                
                if "buttons" in self._original_handlers:
                    ida_kernwin.ask_buttons = self._original_handlers["buttons"]
                    print("Restored ask_buttons handler")
                
                if "text" in self._original_handlers:
                    ida_kernwin.ask_text = self._original_handlers["text"]
                    print("Restored ask_text handler")
                
                if "file" in self._original_handlers:
                    ida_kernwin.ask_file = self._original_handlers["file"]
                    print("Restored ask_file handler")
                
                saved_keys = list(self._original_handlers.keys())
                if saved_keys:
                    print(f"Original handlers restored: {', '.join(saved_keys)}")
                else:
                    print("No original handlers were saved, nothing to restore")
            else:
                print("No original handlers dictionary to restore")
        except Exception as e:
            print(f"Error restoring original handlers: {str(e)}")
            traceback.print_exc() 

    @idaread
    @ida_tool(description="获取函数的引用（被调用的位置）")
    def get_function_references(self, function_name: str) -> Dict[str, Any]:
        """
        获取一个函数被调用的所有位置
        
        Args:
            function_name: 函数名称
            
        Returns:
            包含所有引用的结果字典
        """
        try:
            # 获取函数地址
            function_addr = idaapi.get_name_ea(idaapi.BADADDR, function_name)
            if function_addr == idaapi.BADADDR:
                return {
                    "success": False,
                    "error": f"找不到函数 '{function_name}'",
                    "formatted_response": f"找不到函数 '{function_name}'"
                }
            
            # 验证这是一个函数
            func = idaapi.get_func(function_addr)
            if not func:
                return {
                    "success": False,
                    "error": f"'{function_name}' 不是一个有效的函数",
                    "formatted_response": f"'{function_name}' 不是一个有效的函数"
                }
            
            # 收集引用
            references = []
            for ref in idautils.XrefsTo(function_addr):
                if ref.iscode:  # 只关注代码引用
                    referring_func = idaapi.get_func(ref.frm)
                    if referring_func:
                        references.append({
                            "address": hex(ref.frm),
                            "function_name": idaapi.get_func_name(referring_func.start_ea),
                            "function_address": hex(referring_func.start_ea)
                        })
            
            return {
                "success": True,
                "function_name": function_name,
                "function_address": hex(function_addr),
                "references": references,
                "count": len(references),
                "formatted_response": f"找到 {len(references)} 个对函数 '{function_name}' 的引用"
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"获取函数引用时出错: {str(e)}",
                "formatted_response": f"获取函数引用失败: {str(e)}"
            }

class ScriptSandbox:
    """
    Implements a sandbox environment for safely executing user scripts.
    Restricts access to potentially dangerous operations and modules.
    """
    
    # List of allowed modules that can be imported in the sandbox
    ALLOWED_MODULES = {
        # IDA related modules
        'idaapi', 'idautils', 'idc', 'ida_funcs', 'ida_bytes', 
        'ida_name', 'ida_segment', 'ida_lines', 'ida_hexrays',
        # Basic standard library modules
        'math', 'random', 're', 'datetime', 'time', 'json',
        'collections', 'itertools', 'functools', 'struct',
        # Other safe modules
        'base64', 'hashlib', 'uuid'
    }
    
    # List of specifically disallowed built-in functions
    DISALLOWED_BUILTINS = {
        'exec', 'eval', 'compile', '__import__', 
        'open', 'file', 'input',
        'globals', 'locals', 'vars',
        'memoryview', 'breakpoint',
        'getattr', 'setattr', 'delattr', 'hasattr'
    }
    
    # Regular expressions for detecting potentially malicious code
    DANGEROUS_PATTERNS = [
        # Accessing dangerous dunder methods
        r'__(?:class)?getattribute__',
        r'__(?:base)?subclasses__',
        r'__loader__',
        r'__subclasses__\(\)',
        r'__mro__',
        r'__weakref__',
        
        # System access modules
        r'subprocess\..*',
        r'os\..*',
        r'sys\..*',
        r'socket\..*',
        r'importlib\..*',
        r'shutil\..*',
        r'io\..*',
        r'glob\..*',
        r'tempfile\..*',
        r'pathlib\..*',
        
        # Serialization (potential for code execution)
        r'pickle\..*',
        r'marshal\..*',
        r'shelve\..*',
        r'dill\..*',
        
        # Native code/system interaction
        r'ctypes\..*',
        r'pty\..*',
        r'platform\..*',
        r'multiprocessing\..*',
        r'mmap\..*',
        r'commands\..*',
        r'winreg\..*',
        r'msvcrt\..*',
        r'code\..*',
        
        # Network access
        r'urllib\..*',
        r'http\..*',
        r'ftplib\..*',
        r'ssl\..*',
        r'requests\..*',
        r'xmlrpc\..*',
        r'smtplib\..*',
        
        # File operations
        r'fileinput\..*',
        r'anydbm\..*',
        r'dbm\..*',
        r'zipfile\..*',
        r'tarfile\..*',
        
        # Specific dangerous functions
        r'exec\(',
        r'eval\(',
        r'compile\(',
        r'__import__\(',
        r'open\(',
        r'(?<!\.)\s*input\(',
        r'globals\(\)',
        r'locals\(\)',
        r'getattr\(',
        r'setattr\(',
        r'delattr\(',
        r'hasattr\(',
        
        # Special accessor methods
        r'.__dict__',
        r'.__class__',
        r'.__globals__',
        r'.__getattribute__',
        r'.__setattr__',
        r'.__delattr__',
    ]
    
    @classmethod
    def create_safe_globals(cls) -> Dict[str, Any]:
        """
        Create a restricted globals dictionary for sandbox execution.
        
        Returns:
            A dictionary with restricted built-ins and allowed modules
        """
        # Start with a fresh built-ins dict - safer than modifying the existing one
        safe_builtins = cls._create_safe_builtins()
        
        # Create a sandbox globals dictionary
        sandbox_globals = {
            '__builtins__': safe_builtins,
            # Add allowed IDA modules
            'idaapi': idaapi,
            'idautils': idautils,
            'idc': idc,
            'ida_funcs': ida_funcs,
            'ida_bytes': ida_bytes,
            'ida_name': ida_name,
            'ida_segment': ida_segment,
            'ida_lines': ida_lines,
            'ida_hexrays': ida_hexrays
        }
        
        return sandbox_globals
    
    @classmethod
    def _create_safe_builtins(cls) -> Dict[str, Any]:
        """
        Create a restricted builtins dictionary, removing dangerous functions.
        
        Returns:
            A dictionary with safe built-in functions
        """
        # Create a copy of the built-ins
        safe_builtins = dict(builtins.__dict__)
        
        # Remove disallowed built-ins
        for func_name in cls.DISALLOWED_BUILTINS:
            if func_name in safe_builtins:
                del safe_builtins[func_name]
        
        # Create a safe limited import function
        safe_builtins['__import__'] = cls._create_restricted_import()
        
        return safe_builtins
    
    @classmethod
    def _create_restricted_import(cls) -> Callable:
        """
        Create a restricted import function that only allows specific modules.
        
        Returns:
            A wrapper function for __import__ that only allows safe modules
        """
        original_import = builtins.__import__
        
        def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
            # Check if the module is in the allowed list
            module_base = name.split('.')[0]
            if module_base not in cls.ALLOWED_MODULES:
                raise ImportError(f"Import of '{name}' is not allowed in the sandbox environment")
            return original_import(name, globals, locals, fromlist, level)
        
        return restricted_import
    
    @classmethod
    def check_code_safety(cls, script: str) -> Tuple[bool, str]:
        """
        Check if the script contains potentially dangerous code patterns.
        
        Args:
            script: The script code to check
            
        Returns:
            Tuple of (is_safe, message) - is_safe is True if no dangerous patterns found
        """
        # Make import pattern more comprehensive
        import_pattern = r'^\s*(?:from|import)\s+([a-zA-Z0-9_\.]+)'
        
        # Check for imports of unauthorized modules
        for line in script.splitlines():
            match = re.match(import_pattern, line)
            if match:
                module_name = match.group(1).split('.')[0]
                if module_name not in cls.ALLOWED_MODULES:
                    return False, f"Import of unauthorized module: {module_name}"
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if re.search(pattern, script):
                return False, f"Dangerous code pattern detected: {pattern}"
        
        # Additional checks for direct attribute access
        attribute_patterns = [
            r'__dict__',
            r'__globals__',
            r'__code__',
            r'__func__',
            r'__builtins__'
        ]
        
        for pattern in attribute_patterns:
            if re.search(pattern, script):
                return False, f"Dangerous attribute access detected: {pattern}"
        
        # Check for timeout evasion techniques
        timeout_evasion_patterns = [
            # Threading/multiprocessing to bypass timeout
            r'threading\.',
            r'Thread\(',
            r'multiprocessing\.',
            r'Process\(',
            r'Pool\(',
            # Long sleeps
            r'(?:time\.)?sleep\s*\(\s*[0-9]+[0-9.]*\s*\)',
            # Signals
            r'signal\.',
            # Infinite loops patterns
            r'while\s+True',
            r'while\s+1',
            r'while\s+not\s+False',
            r'for\s+.*\s+in\s+(?:iter|range)\s*\(\s*(?:[0-9]+\s*,\s*)*\s*\)',  # Suspicious iteration constructs
            # Anti-sandbox patterns
            r'(?:gc|sys|atexit)\.(?:set|register|add)(?:trace|callback|hook)',
        ]
        
        for pattern in timeout_evasion_patterns:
            if re.search(pattern, script):
                return False, f"Potential timeout evasion detected: {pattern}"
        
        # Check for IDA-specific dangerous actions
        ida_dangerous_patterns = [
            # Functions that could crash IDA or modify the database unexpectedly
            r'ida_loader\.load_',
            r'ida_idp\.set_',
            r'ida_diskio\.',
            r'ida_auto\.reanalyze',
            # File operations
            r'idc\.load',
            r'idc\.save',
            r'idc\.exec',
            r'idc\.system',
            r'idc\.qexit',
            r'idaapi\.qexit',
            # UI manipulation or automation
            r'ida_kernwin\.process_ui_action',
            r'ida_kernwin\.create_desktop',
            r'ida_kernwin\.restore_desktop'
        ]
        
        for pattern in ida_dangerous_patterns:
            if re.search(pattern, script):
                return False, f"Dangerous IDA operation detected: {pattern}"
        
        return True, "Script passed safety check"

class ResourceMonitor:
    """
    Monitor and limit resource usage for scripts running in the sandbox.
    """
    
    # Maximum allowed memory usage in bytes (default: 500MB)
    MAX_MEMORY = 500 * 1024 * 1024
    
    # Resource consumption was above threshold
    resource_exceeded = False
    
    # Error message if resources were exceeded
    error_message = ""
    
    @classmethod
    def reset(cls):
        """Reset monitoring state"""
        cls.resource_exceeded = False
        cls.error_message = ""
    
    @classmethod
    def check_memory_usage(cls) -> Tuple[bool, int]:
        """
        Check current memory usage.
        
        Returns:
            Tuple of (is_within_limits, current_usage_bytes)
        """
        try:
            if platform.system() == 'Windows':
                # Windows-specific memory check using psutil if available
                try:
                    import psutil
                    process = psutil.Process()
                    memory_info = process.memory_info()
                    memory_usage = memory_info.rss  # Resident Set Size in bytes
                except ImportError:
                    # Fallback if psutil is not available
                    memory_usage = 0  # Can't check on Windows without psutil
                    return (True, memory_usage)
            else:
                # Unix/Linux/macOS
                rusage = resource.getrusage(resource.RUSAGE_SELF)
                # maxrss is in kilobytes on Unix
                memory_usage = rusage.ru_maxrss * 1024
            
            return (memory_usage <= cls.MAX_MEMORY, memory_usage)
        except Exception as e:
            print(f"Error checking memory usage: {str(e)}")
            # On error, assume usage is within limits to avoid false positives
            return (True, 0)
    
    @classmethod
    def monitor_resources(cls, interval=1.0):
        """
        Periodically check resource usage and set flag if thresholds are exceeded.
        
        Args:
            interval: Check interval in seconds
        """
        start_time = time.time()
        try:
            while True:
                # Check memory usage
                is_memory_ok, memory_usage = cls.check_memory_usage()
                if not is_memory_ok:
                    cls.resource_exceeded = True
                    cls.error_message = f"Script exceeded memory limit of {cls.MAX_MEMORY / (1024*1024):.1f}MB (used {memory_usage / (1024*1024):.1f}MB)"
                    break
                
                # Check if we've been running this monitoring thread too long
                elapsed = time.time() - start_time
                if elapsed > 60:  # 1 minute max for monitoring thread
                    break
                    
                time.sleep(interval)
        except Exception as e:
            print(f"Error in resource monitor: {str(e)}")