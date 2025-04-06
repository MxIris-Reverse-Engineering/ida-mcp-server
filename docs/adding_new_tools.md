# 添加新的IDA MCP工具函数

本文档介绍了如何使用改进后的注解系统在IDA MCP服务器中添加新的工具函数。

## 直接在IDAMCPCore中添加工具

最简单的方法是直接在`IDAMCPCore`类中添加一个方法，并使用`@ida_tool`装饰器标记它：

```python
from typing import Dict, Any, List

class IDAMCPCore:
    # 现有方法...
    
    @idaread  # 首先应用IDA读取装饰器（如果是读取操作）
    @ida_tool(description="获取所有字符串")
    def get_all_strings(self, max_count: int = 100) -> Dict[str, Any]:
        """
        获取当前二进制文件中的所有字符串
        
        Args:
            max_count: 最大返回数量
            
        Returns:
            包含字符串列表的字典
        """
        strings = []
        # 实现获取字符串的逻辑...
        
        return {
            "success": True,
            "strings": strings,
            "count": len(strings),
            "formatted_response": f"找到 {len(strings)} 个字符串"
        }
```

这样，系统会自动将此方法注册为名为`ida_get_all_strings`的工具，客户端可以直接调用它。

## 关于装饰器的顺序

注意装饰器的应用顺序：

1. 首先应用`@idaread`或`@idawrite`装饰器（这些确保函数在IDA的主线程中执行）
2. 然后应用`@ida_tool`装饰器（这将函数注册为MCP工具）

正确的顺序是：

```python
@idaread  # 或 @idawrite，根据操作类型
@ida_tool(description="工具描述")
def your_function(self, param1: type1, param2: type2) -> Dict[str, Any]:
    # 实现...
```

## 类型提示和参数验证

工具函数应该使用Python的类型提示系统，这有助于：
1. 自动生成API文档
2. 参数验证和转换
3. 改善代码可读性

例如：

```python
@idawrite
@ida_tool(description="重命名多个函数")
def rename_multiple_functions(self, renames: List[Dict[str, str]]) -> Dict[str, Any]:
    """
    批量重命名多个函数
    
    Args:
        renames: 包含old_name和new_name键的字典列表
        
    Returns:
        操作结果
    """
    results = []
    success_count = 0
    
    for rename in renames:
        old_name = rename.get("old_name")
        new_name = rename.get("new_name")
        
        if old_name and new_name:
            result = self.rename_function(old_name, new_name)
            if result.get("success", False):
                success_count += 1
            results.append(result)
    
    return {
        "success": success_count > 0,
        "renamed": success_count,
        "total": len(renames),
        "results": results,
        "formatted_response": f"成功重命名 {success_count}/{len(renames)} 个函数"
    }
```

## 参数转换

系统会自动尝试将参数转换为您在函数签名中指定的类型。特别地，对于`address`参数，系统会自动尝试将字符串地址（如`"0x1234"`）转换为整数。

常见的类型转换：
- 字符串转整数
- 字符串转浮点数
- 字符串转布尔值（"true"/"false"）
- 字符串地址转整数地址

## 返回值格式

为了保持一致性，所有工具函数都应返回一个包含以下键的字典：

- `success`: 布尔值，表示操作是否成功
- `formatted_response`: 字符串，用于显示给用户的友好消息
- `error`: （仅在失败时）错误信息

根据工具的不同，可能还需要其他键来提供更多信息。例如：
- 对于返回数据的工具，应增加特定键来包含结果数据
- 对于批量操作，可增加计数器和详细结果列表

## 错误处理

工具函数应该捕获所有可能的异常，并返回适当的错误信息：

```python
@idaread
@ida_tool(description="获取某个内存地址的数据")
def get_memory_data(self, address: str, size: int = 16) -> Dict[str, Any]:
    """获取特定内存地址的原始数据"""
    try:
        # 将地址转换为整数
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        # 读取数据
        data = idaapi.get_bytes(addr, size)
        if not data:
            return {
                "success": False, 
                "error": f"无法读取地址 {address} 的数据",
                "formatted_response": f"无法读取地址 {address} 的数据"
            }
            
        # 返回成功结果
        return {
            "success": True,
            "address": address,
            "data": data.hex(),
            "size": len(data),
            "formatted_response": f"从地址 {address} 读取了 {len(data)} 字节数据"
        }
    except ValueError:
        return {
            "success": False,
            "error": f"无效的地址格式: {address}",
            "formatted_response": f"无效的地址格式: {address}"
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"读取内存数据时出错: {str(e)}",
            "formatted_response": f"读取内存数据失败: {str(e)}"
        }
```

## 自动工具注册

当插件初始化时，系统会自动扫描`IDAMCPCore`类中所有带有`@ida_tool`装饰器的方法，并将它们注册为可用的MCP工具。这个过程是自动的，您无需手动编写工具模型或更新枚举。

## 内部工具函数的复用

如果你的工具需要调用其他IDAMCPCore方法，可以直接使用`self`引用：

```python
@idawrite
@ida_tool(description="在多个地址添加注释")
def add_multiple_comments(self, comments: List[Dict[str, str]]) -> Dict[str, Any]:
    """在多个地址添加注释"""
    results = []
    success_count = 0
    
    for comment_info in comments:
        address = comment_info.get("address")
        comment_text = comment_info.get("comment")
        is_repeatable = comment_info.get("is_repeatable", False)
        
        if address and comment_text:
            # 重用现有的add_assembly_comment方法
            result = self.add_assembly_comment(address, comment_text, is_repeatable)
            if result.get("success", False):
                success_count += 1
            results.append(result)
    
    return {
        "success": success_count > 0,
        "commented": success_count,
        "total": len(comments),
        "results": results,
        "formatted_response": f"成功添加 {success_count}/{len(comments)} 条注释"
    }
```

## 兼容性处理

为了确保在插件初始化前模块加载时不会出错，系统包含一个`ida_tool`装饰器的后备版本。这使得你可以直接在模块顶层导入和使用装饰器，而不必担心初始化顺序问题。

## 完整示例

下面是一个添加新工具函数的完整示例，您可以直接复制到`ida_mcp_core.py`文件中：

```python
from typing import Dict, Any, List

class IDAMCPCore:
    # 现有的方法...
    
    @idaread
    @ida_tool(description="获取所有导入函数")
    def get_imports(self) -> Dict[str, Any]:
        """获取当前二进制文件的所有导入函数"""
        import idautils
        
        imports = []
        for i in idautils.Imports():
            imports.append({
                "module": i,
                "functions": [
                    {"name": idaapi.get_name(ea), "address": hex(ea)}
                    for ea in idautils.Functions(idautils.Segments())
                ]
            })
            
        return {
            "success": True,
            "imports": imports,
            "count": len(imports),
            "formatted_response": f"找到 {len(imports)} 个导入模块"
        }
```

添加此函数后，重启IDA Pro和MCP插件，新工具将自动可用于客户端调用，无需额外的配置。 