# Export the decorator for use in ida_mcp_core.py

def get_ida_tool_decorator():
    """
    This function will be imported by ida_mcp_core.py to get the actual ida_tool decorator.
    It returns a placeholder function that the register_core_tools will replace later.
    """
    def ida_tool(description=None, tool_name=None):
        """Temporary decorator that marks a function as a tool for later registration"""
        def decorator(func):
            # Set attributes that will be recognized by register_core_tools
            func.__ida_tool__ = True
            func.__ida_tool_description__ = description
            func.__ida_tool_name__ = tool_name
            return func
        return decorator
    
    return ida_tool
