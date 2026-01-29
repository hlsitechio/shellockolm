# 🤖 MCP Server Setup - Use Shellockolm in AI Tools

**Shellockolm MCP Server** lets AI assistants (Claude, Copilot, Codex) scan your code for vulnerabilities directly.

---

## 🎯 What You Get

AI assistants can now:
- ✅ **Scan projects** for 32 CVEs automatically
- ✅ **Live probe** URLs for exploits
- ✅ **Auto-fix** vulnerabilities with one command
- ✅ **Check CVE details** in real-time
- ✅ **List all CVEs** with filters

---

## ⚡ Quick Setup

### 1️⃣ For Claude Desktop (Anthropic)

**Windows:**
```powershell
# Copy config to Claude Desktop settings
$claudeConfig = "$env:APPDATA\Claude\claude_desktop_config.json"
$config = Get-Content .mcp-config.json | ConvertFrom-Json
$config.mcpServers.shellockolm.cwd = $PWD.Path
$config | ConvertTo-Json -Depth 10 | Set-Content $claudeConfig
Write-Host "✅ Shellockolm MCP configured for Claude Desktop"
```

**macOS/Linux:**
```bash
# Copy config to Claude Desktop settings
CLAUDE_CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
jq --arg cwd "$PWD" '.mcpServers.shellockolm.cwd = $cwd' .mcp-config.json > "$CLAUDE_CONFIG"
echo "✅ Shellockolm MCP configured for Claude Desktop"
```

**Manual Setup:**
1. Open Claude Desktop settings
2. Go to "Developer" → "Edit Config"
3. Add:
```json
{
  "mcpServers": {
    "shellockolm": {
      "command": "python",
      "args": ["/path/to/shellockolm/src/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/path/to/shellockolm/src"
      }
    }
  }
}
```

---

### 2️⃣ For GitHub Copilot CLI

**Setup:**
```bash
# Add to Copilot CLI config
gh copilot config set mcp.servers.shellockolm \
  '{"command":"python","args":["src/mcp_server.py"],"cwd":"'$PWD'"}'
```

**Usage:**
```bash
# Ask Copilot to scan your project
gh copilot suggest "scan this project for vulnerabilities using shellockolm"

# Or in chat mode
gh copilot chat
> Use shellockolm to scan for React CVEs
```

---

### 3️⃣ For Cursor IDE

**Setup:**
1. Open Cursor Settings (⌘, or Ctrl+,)
2. Search for "MCP Servers"
3. Click "Add MCP Server"
4. Enter:
   - **Name:** `shellockolm`
   - **Command:** `python`
   - **Args:** `["src/mcp_server.py"]`
   - **Working Directory:** `/path/to/shellockolm`

**Usage:**
```
# In Cursor chat
@shellockolm scan this directory for CVEs
@shellockolm check CVE-2025-55182
@shellockolm fix this vulnerability
```

---

### 4️⃣ For Continue.dev

**Setup:**
Add to `~/.continue/config.json`:
```json
{
  "mcpServers": [
    {
      "name": "shellockolm",
      "command": "python",
      "args": ["src/mcp_server.py"],
      "cwd": "/path/to/shellockolm"
    }
  ]
}
```

---

### 5️⃣ For Any MCP-Compatible Client

**Generic stdio configuration:**
```json
{
  "command": "python",
  "args": ["src/mcp_server.py"],
  "cwd": "/absolute/path/to/shellockolm",
  "env": {
    "PYTHONPATH": "/absolute/path/to/shellockolm/src"
  }
}
```

---

## 🧪 Test Your Setup

### Start MCP Server Manually
```bash
cd /path/to/shellockolm
python src/mcp_server.py
```

You should see:
```
Shellockolm MCP Server v2.0
Listening on stdio...
Ready for requests
```

### Test with MCP Inspector (Development Tool)
```bash
npm install -g @modelcontextprotocol/inspector
mcp-inspector python src/mcp_server.py
```

---

## 🛠️ Available MCP Tools

### 1. **scan_directory**
Scan a directory for all 32 tracked CVEs.

**Example (in AI chat):**
```
Scan /path/to/my-react-app for vulnerabilities
```

**Parameters:**
- `path` (required): Directory to scan
- `recursive` (default: true): Scan subdirectories
- `scanner` (optional): Specific scanner (react, nextjs, npm, etc.)

---

### 2. **scan_live**
Probe a live URL for exploitable vulnerabilities.

**Example:**
```
Check if https://my-app.com is vulnerable to CVE-2025-55182
```

**Parameters:**
- `url` (required): URL to probe
- `scanner` (default: "all"): nextjs, n8n, or all
- `timeout` (default: 10): Request timeout

---

### 3. **fix_vulnerability**
Automatically patch a vulnerability with backup.

**Example:**
```
Fix CVE-2025-55182 in /path/to/package.json
```

**Parameters:**
- `path` (required): Path to package.json
- `cve_id` (required): CVE to fix
- `backup` (default: true): Create backup before patching

---

### 4. **check_cve**
Get detailed information about a specific CVE.

**Example:**
```
What is CVE-2025-55182?
```

**Parameters:**
- `cve_id` (required): CVE identifier

---

### 5. **list_cves**
List all tracked CVEs with filters.

**Example:**
```
Show all critical React CVEs
```

**Parameters:**
- `severity` (optional): CRITICAL, HIGH, MEDIUM, LOW
- `package` (optional): Filter by package (react, next, node, etc.)
- `exploitable` (optional): Only show exploitable CVEs

---

## 🔧 Troubleshooting

### MCP Server Won't Start

**Check Python path:**
```bash
which python  # Should show Python 3.10+
python --version
```

**Check dependencies:**
```bash
pip install -r requirements.txt
```

**Test imports:**
```bash
cd /path/to/shellockolm
python -c "import sys; sys.path.insert(0, 'src'); from mcp_server import server; print('OK')"
```

### AI Tool Can't Find Server

**Verify config path:**
- Claude Desktop: `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- Check that `cwd` is an **absolute path**

**Check logs:**
- Claude Desktop: Help → Show Logs
- Look for MCP connection errors

### Tools Don't Respond

**Test with MCP Inspector:**
```bash
mcp-inspector python src/mcp_server.py
# Try calling scan_directory from the inspector
```

**Enable debug logging:**
```bash
export SHELLOCKOLM_LOG_LEVEL=DEBUG
python src/mcp_server.py
```

---

## 📚 Examples

### Example 1: Scan a React Project
**Prompt to AI:**
```
Use shellockolm to scan my React project at ~/code/my-app
```

**AI Response:**
```
Scanning ~/code/my-app...

Found 3 vulnerabilities:
- CVE-2025-55182 (CRITICAL): React Server Components RCE
- CVE-2025-55130 (HIGH): Node.js permission bypass
- CLAWDBOT-PLAINTEXT-CREDS (HIGH): Exposed API tokens

Would you like me to fix these?
```

### Example 2: Check a Specific CVE
**Prompt:**
```
What is CVE-2025-55182 and am I affected?
```

**AI Response:**
```
CVE-2025-55182: React Server Components Remote Code Execution
- CVSS: 10.0 (CRITICAL)
- Affects: React 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Fix: Upgrade to React 19.3.0+

Checking your project... [scans automatically]
✅ Not vulnerable - you're using React 18.2.0
```

### Example 3: Live Probe a URL
**Prompt:**
```
Is my Next.js app vulnerable? https://myapp.vercel.app
```

**AI Response:**
```
Probing https://myapp.vercel.app...

⚠️ VULNERABLE: Next.js middleware bypass detected
- CVE-2025-55128 (CVSS 9.1)
- Authentication can be bypassed
- Fix: Upgrade Next.js to 15.2.0+
```

---

## 🚀 Advanced Usage

### Custom Scan Workflows
Create AI workflows that automatically:
1. Scan on every commit
2. Auto-fix low-risk CVEs
3. Create GitHub issues for critical findings
4. Generate security reports

### Integration with CI/CD
Use MCP tools in AI-powered CI/CD:
```
Ask AI: "Scan this PR for security issues using shellockolm"
→ AI uses MCP to scan
→ AI comments on PR with findings
→ AI can auto-fix if you approve
```

---

## 📖 Learn More

- **MCP Protocol:** https://modelcontextprotocol.io
- **Shellockolm Docs:** https://github.com/hlsitechio/shellockolm
- **Report Issues:** https://github.com/hlsitechio/shellockolm/issues

---

**Built with 🔍 by @hlsitechio & AI (Claude + GitHub Copilot)**
