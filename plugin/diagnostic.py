"""
IDA MCP Server Plugin Diagnostic Tool

This script should be run from within IDA Python console to diagnose
issues with tool registration and execution in the IDA MCP Server plugin.
"""

import sys
import traceback
import inspect

try:
    # Add verbose logging
    import logging
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger("ida_mcp_diagnostic")
    logger.setLevel(logging.DEBUG)
    
    # Helper to print sections
    def print_section(title):
        print("\n" + "=" * 50)
        print(f" {title} ".center(50, "="))
        print("=" * 50)
    
    print_section("IDA MCP PLUGIN DIAGNOSTIC")
    
    # 1. Check imports
    print_section("CHECKING IMPORTS")
    
    # Try importing core modules
    try:
        import ida_mcp_server_plugin
        print(f"[√] Successfully imported ida_mcp_server_plugin")
        print(f"    Location: {ida_mcp_server_plugin.__file__}")
    except ImportError as e:
        print(f"[✗] Failed to import ida_mcp_server_plugin: {str(e)}")
        sys.exit(1)
    
    # Check for IDAMCPCore
    try:
        from ida_mcp_server_plugin.ida_mcp_core import IDAMCPCore, mark_as_tool, ida_tool
        print(f"[√] Successfully imported IDAMCPCore")
        print(f"    mark_as_tool function: {mark_as_tool}")
        print(f"    ida_tool function: {ida_tool}")
        
        # Check if they're the same
        if ida_tool is mark_as_tool:
            print(f"[i] Note: ida_tool and mark_as_tool are the same function")
        else:
            print(f"[i] Note: ida_tool and mark_as_tool are different functions")
    except ImportError as e:
        print(f"[✗] Failed to import IDAMCPCore: {str(e)}")
        sys.exit(1)
    
    # 2. Check IDAMCPCore methods
    print_section("CHECKING CORE METHODS")
    
    # Create core instance
    core = IDAMCPCore()
    print(f"[√] Created IDAMCPCore instance")
    
    # Get methods
    methods = [m for m in dir(core) if callable(getattr(core, m)) and not m.startswith('_')]
    print(f"[i] Found {len(methods)} public methods in IDAMCPCore")
    
    # Check for methods with __ida_tool__ attribute
    tool_methods = []
    for method_name in methods:
        method = getattr(core, method_name)
        has_tool_attr = hasattr(method, "__ida_tool__") and getattr(method, "__ida_tool__")
        if has_tool_attr:
            tool_methods.append(method_name)
            
            # Get description
            desc = getattr(method, "__ida_tool_description__", "No description")
            name = getattr(method, "__ida_tool_name__", f"ida_{method_name}")
            
            print(f"[√] Method '{method_name}' has __ida_tool__ attribute")
            print(f"    Tool name: {name}")
            print(f"    Description: {desc}")
    
    if not tool_methods:
        print(f"[✗] No methods with __ida_tool__ attribute found!")
        print(f"    This suggests the decorator is not being applied correctly.")
    else:
        print(f"[√] Found {len(tool_methods)} methods with __ida_tool__ attribute")
    
    # 3. Check tool registration
    print_section("CHECKING TOOL REGISTRATION")
    
    # Get _tool_registry and _tool_metadata
    try:
        from ida_mcp_server_plugin import _tool_registry, _tool_metadata
        print(f"[√] Accessed _tool_registry and _tool_metadata")
        print(f"[i] _tool_registry has {len(_tool_registry)} entries")
        print(f"[i] _tool_metadata has {len(_tool_metadata)} entries")
        
        # Check for overlap with tool_methods
        registered_methods = set()
        for tool_name, metadata in _tool_metadata.items():
            if "core_method" in metadata:
                registered_methods.add(metadata["core_method"])
        
        print(f"[i] _tool_metadata contains {len(registered_methods)} core methods")
        
        # Check for methods that should be registered but aren't
        missing_methods = set(tool_methods) - registered_methods
        if missing_methods:
            print(f"[✗] {len(missing_methods)} methods with __ida_tool__ attribute not in _tool_metadata:")
            for method in missing_methods:
                print(f"    - {method}")
        else:
            print(f"[√] All methods with __ida_tool__ attribute are in _tool_metadata")
    except ImportError as e:
        print(f"[✗] Failed to access _tool_registry and _tool_metadata: {str(e)}")
    
    # 4. Try registering tools manually
    print_section("TRYING MANUAL REGISTRATION")
    
    try:
        from ida_mcp_server_plugin import register_core_tools
        print(f"[√] Successfully imported register_core_tools")
        
        # Register tools
        print(f"[i] Calling register_core_tools...")
        register_core_tools(core)
        
        # Check registered tools again
        from ida_mcp_server_plugin import _tool_registry
        print(f"[i] After registration, _tool_registry has {len(_tool_registry)} entries")
        
        # List registered tools
        print(f"[i] Registered tools:")
        for tool_name in _tool_registry:
            print(f"    - {tool_name}")
    except Exception as e:
        print(f"[✗] Error during manual registration: {str(e)}")
        traceback.print_exc()
    
    # 5. Create tool executor and test execution
    print_section("TESTING TOOL EXECUTION")
    
    try:
        from ida_mcp_server_plugin import ToolExecutor
        
        # Create executor
        tool_executor = ToolExecutor(core)
        print(f"[√] Created ToolExecutor")
        
        # Get tool names
        tool_names = tool_executor.get_tool_names()
        print(f"[i] ToolExecutor reports {len(tool_names)} tools:")
        for tool_name in tool_names:
            print(f"    - {tool_name}")
        
        # Test execute a simple tool if available
        if "ida_get_all_strings" in tool_names:
            print(f"[i] Testing execution of ida_get_all_strings...")
            result = tool_executor.execute_tool("ida_get_all_strings", {"max_count": 10, "min_length": 4})
            if result.get("success", False):
                print(f"[√] Successfully executed ida_get_all_strings")
                print(f"    Found {result.get('count', 0)} strings")
            else:
                print(f"[✗] Error executing ida_get_all_strings: {result.get('error', 'Unknown error')}")
        else:
            print(f"[i] ida_get_all_strings not available for testing")
    except Exception as e:
        print(f"[✗] Error testing tool execution: {str(e)}")
        traceback.print_exc()
    
    print_section("DIAGNOSTIC COMPLETE")
    print("If you're having issues with tool registration or execution, please share this output.")

except Exception as e:
    print(f"Error running diagnostic: {str(e)}")
    traceback.print_exc() 