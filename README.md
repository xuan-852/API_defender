# Secret Guardian - API 密钥防护工具

> 在 Git 提交/推送前自动扫描敏感信息，防止 API Key、密码、Token 泄露到公共仓库。

## 前言
由于本人在某个项目不小心将aip key 泄露到了公共仓库，导致一日内api的余额被消耗光，导致项目无法正常运行。因此，我决定开发这个工具，来防止类似的情况发生。

## 免责声明
本工具仅用于防止敏感信息泄露，不涉及任何商业用途，并且无法确保100%防止敏感信息泄露，因此在使用时请谨慎，仅作为辅助工具。** 

## 文件说明

| 文件 | 用途 |
|------|------|
| `secret_scanner.py` | 核心扫描引擎 — 正则匹配各类敏感信息 |
| `guardian.py` | 系统托盘守护程序 — 后台实时监控文件变化 |
| `setup_guardian.ps1` | 一键安装脚本 |
| `test_secret_scan.py` | 测试文件（含已撤销的密钥，供验证用） |

## 快速安装

```powershell
# 1. 安装 Git 钩子
python "D:\tool\aip_defender\secret_scanner.py" install-hook

# 2. 确认全局钩子已生效
git config --global core.hooksPath
# 应输出: C:\Users\25295\.secret-guardian\git-hooks
```

安装后，**所有 Git 仓库**在 `git commit` 和 `git push` 时都会自动触发扫描。

## 手动扫描

```powershell
# 扫描单个文件
python "D:\tool\aip_defender\secret_scanner.py" scan "D:\Project\config.py"

# 扫描整个目录
python "D:\tool\aip_defender\secret_scanner.py" scan "D:\Project\"

# 扫描 Git 暂存区
python "D:\tool\aip_defender\secret_scanner.py" pre-commit

# 扫描 Git 推送内容
python "D:\tool\aip_defender\secret_scanner.py" pre-push
```

## 绕过检查（紧急情况）

```bash
git commit --no-verify -m "message"
git push --no-verify
```

## 开机自启守护程序

编辑 `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\SecretGuardian.vbs`，
确保内容为：

```vbscript
Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "pythonw ""D:\tool\aip_defender\guardian.py""", 0, False
```

## 工作原理

```
Git commit/push
    ↓
全局 Git 钩子 (MSYS2/.bat)
    ↓
Secret Scanner (正则匹配)
    ↓
┌─ 有敏感信息 → 阻断操作，列出详情
└─ 无敏感信息 → 放行
```

## 支持的检测项

- OpenAI / DeepSeek / Anthropic / Gemini API Key
- 百度 API Key & Secret Key
- 阿里云 & 腾讯云 AccessKey
- 微信/支付宝/钉钉 Secret
- JWT Token
- 各类 `sk-` / `sk-` 打头的密钥
- 通用密码/令牌模式
- Private Key (RSA/EC/OpenSSH)

## 测试扫描是否正常

将以下内容保存为任意 `.py` 文件（如 `test_key.py`），然后运行扫描：

```python
# 测试用密钥（已吊销，仅用于验证扫描功能）
BAIDU_API_KEY = "LVZcNhtn584JqOPB9UCsBE4H"
BAIDU_SECRET_KEY = "QpoVPPhETyWK7yLC8L2TLRzrSBALASG3"
DEEPSEEK_API_KEY = "sk-717fd68ac7964fcabd7733cf8917f5a8"
```

```powershell
python "D:\tool\aip_defender\secret_scanner.py" scan "D:\path\to\test_key.py"
```

预期输出：应检测到 3 条敏感信息（百度 API Key、百度 Secret Key、DeepSeek API Key），并返回 **`[!] Found 3 secrets`**。
