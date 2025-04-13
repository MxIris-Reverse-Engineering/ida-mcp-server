# IDA MCP Server

IDA MCP (Machine Code Processor) Server是一个IDA Pro插件，提供与MCP客户端的集成，使外部工具能够通过API与IDA交互。

## 特性

- 简单易用的API接口
- 安全的网络通信
- 支持远程函数调用
- 自动类型转换和参数验证
- 轻松扩展，添加新工具

## 最近改进

- **装饰器系统**: 添加了`@ida_tool`装饰器，简化了新工具的添加
- **自动工具注册**: 无需手动创建枚举或模型类，直接注解IDAMCPCore方法
- **类型提示支持**: 使用Python类型提示自动验证和转换参数
- **无样板代码**: 大大减少了添加新功能所需的代码量
- **迁移现有工具**: 完成了所有现有工具到新系统的迁移

## 新增工具示例

最新版本添加了一些有用的新工具：

- **get_all_strings**: 获取当前二进制文件中的所有字符串
- **get_function_references**: 获取函数的所有引用（被调用位置）

## 快速使用

启动IDA Pro，然后通过Edit->Plugins->IDA MCP Server菜单或使用Ctrl-Alt-M快捷键启动服务器。

## 为开发者添加新工具

添加新工具现在非常简单：

1. 在`ida_mcp_core.py`文件中找到`IDAMCPCore`类
2. 添加新方法，使用`@ida_tool`装饰器标记
3. 确保使用适当的类型提示和文档
4. 重启插件

示例：

```python
@idaread
@ida_tool(description="获取当前二进制文件中的所有字符串")
def get_all_strings(self, max_count: int = 1000) -> Dict[str, Any]:
    """获取当前二进制文件中的所有字符串"""
    # 实现...
    return {
        "success": True,
        "strings": strings,
        "count": len(strings),
        "formatted_response": f"找到 {len(strings)} 个字符串"
    }
```

更多详细信息，请参阅[添加新工具的文档](docs/adding_new_tools.md)。

## 技术文档

- [添加新工具指南](docs/adding_new_tools.md)
- [API参考文档](docs/api_reference.md)
- [协议规范](docs/protocol.md)

## 许可证

[MIT](LICENSE)
