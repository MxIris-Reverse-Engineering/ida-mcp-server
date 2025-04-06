# import idapro
import traceback
import idaapi
import idautils
import idc
import ida_funcs
import idaapi
import ida_name
import ida_hexrays
import ida_funcs
import idautils
import sys
sys.path.append('..')
from plugin.ida_mcp_server_plugin.ida_mcp_core import IDAMCPCore
# idapro.open_database("/Volumes/FrameworkLab/Dyld-Shared-Cache/macOS/15.1/dyld_shared_cache_arm64e-LaunchServices.i64", True)  # 替换为你的数据库路径

# core = IDAMCPCore()
# print(core.execute_script("import idautils\nimport idc\n\ncurrent_ea = idc.here()\ncurrent_func = idc.get_func_name(current_ea)\n\nif current_func:\n    print(f'当前函数名: {current_func}')\n    func_addr = idc.get_name_ea_simple(current_func)\n    print(f'函数地址: {hex(func_addr)}')\n    \n    print('\\n引用此函数的位置：')\n    for xref in idautils.XrefsTo(func_addr):\n        print(f'从地址 {hex(xref.frm)} 引用')\n        \n    print('\\n此函数引用的位置：')\n    for addr in idautils.FuncItems(func_addr):\n        for xref in idautils.XrefsFrom(addr):\n            print(f'在地址 {hex(addr)} 引用了 {hex(xref.to)}')\nelse:\n    print('错误：未能获取当前函数')"))
# print(core.get_current_function_decompiled())
# print(core.get_current_function_assembly())
# print(core.get_function_decompiled_by_name("-[SPSpotlightPanel canBecomeMainWindow]"))
# print(core.get_function_assembly_by_name("-[SPSpotlightPanel canBecomeMainWindow]"))
# print(core.rename_local_variable("-[SPIndexingView init]", "v3", "label"))
# idapro.close_database()

import ida_graph
import ida_kernwin

viewer = ida_kernwin.get_current_viewer()
if viewer:
    graph_viewer = ida_graph.get_graph_viewer(viewer)
    node_id = ida_graph.viewer_get_curnode(graph_viewer)
    if node_id != -1:
        print(f"Node ID: {node_id}")
        node_info = ida_graph.node_info_t()
        is_ok = ida_graph.viewer_get_node_info(graph_viewer, node_info, node_id)
        print(is_ok, node_info.text)                


