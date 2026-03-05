# macOS 微信数据库解密

提取微信 (WeChat) 数据库密钥，解密 SQLCipher 加密的本地数据库，导出聊天记录。支持 MCP Server，让 AI 直接查询微信数据。

## 快速开始

### 1. 前置条件

- macOS arm64，微信 4.x
- 禁用 SIP：`csrutil disable`
- 安装依赖：`brew install llvm sqlcipher`

### 2. 提取密钥

确保微信已登录并正在运行：

```bash
PYTHONPATH=$(lldb -P) python3 find_key_memscan.py
```

密钥保存到 `wechat_keys.json`。

### 3. 解密数据库

```bash
python3 decrypt_db.py
```

### 4. 导出聊天记录

```bash
# 列出所有会话
python3 export_messages.py

# 导出指定会话（支持模糊匹配联系人名）
python3 export_messages.py -c "卡比"
python3 export_messages.py -c wxid_xxx
python3 export_messages.py -c 12345@chatroom

# 导出最近 N 条
python3 export_messages.py -c "卡比" -n 50

# 搜索关键词
python3 export_messages.py -s "关键词"

# 导出所有会话
python3 export_messages.py --all
```

### 5. MCP Server（让 AI 直接查询）

安装依赖并注册到 Claude Code：

```bash
pip3 install fastmcp
claude mcp add wechat -- python3 $(pwd)/mcp_server.py
```

注册后 AI 可以直接调用以下能力：

| Tool | 功能 |
|------|------|
| `get_recent_sessions` | 获取最近会话列表 |
| `get_chat_history` | 查看聊天记录（支持模糊匹配） |
| `search_messages` | 跨会话搜索关键词 |
| `get_contacts` | 搜索联系人 |

## Thanks

- [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt) — 内存搜索方案参考
