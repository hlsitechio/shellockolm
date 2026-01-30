# 🎬 MCP Usage Examples - Real Conversations

**See exactly how to use Shellockolm in different AI tools.**

---

## 🟣 Claude Desktop Examples

### Example 1: Basic Scan

**You:**
```
Scan this project for vulnerabilities
```

**Claude:**
```
I'll scan the current directory using shellockolm...

[Calls: scan_directory(path=".", recursive=true)]

Found 5 vulnerabilities:

CRITICAL (1):
- CVE-2025-55182: React Server Components RCE
  Package: react@19.0.0
  Fix: Upgrade to React 19.3.0+

HIGH (3):
- CVE-2025-55130: Node.js Symlink Permission Bypass
- CVE-2025-55128: Next.js Middleware Authentication Bypass
- CLAWDBOT-CREDS: Exposed API tokens in .env file

MEDIUM (1):
- CVE-2025-29927: npm package malware (jsonpath-plus)

Would you like me to:
1. Show detailed remediation steps?
2. Generate a full report?
3. Help fix these automatically?
```

---

### Example 2: Check Specific CVE

**You:**
```
What is CVE-2025-55182? Am I vulnerable?
```

**Claude:**
```
Let me check that CVE for you...

[Calls: get_cve_info(cve_id="CVE-2025-55182")]

CVE-2025-55182: React Server Components Remote Code Execution
- CVSS Score: 10.0 (CRITICAL)
- Severity: CRITICAL
- Affected: React 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Fixed in: React 19.3.0+

Description:
Pre-authentication RCE in React Server Components allows 
attackers to execute arbitrary code by exploiting unsafe 
deserialization in server-side rendering.

Now let me scan your project...

[Calls: scan_directory(path=".", scanner="react")]

✅ Good news! Your project uses React 18.2.0
You are NOT vulnerable to this CVE.

However, I recommend staying updated with security patches.
```

---

### Example 3: Live Website Check

**You:**
```
Is https://myapp.vercel.app vulnerable to Next.js exploits?
```

**Claude:**
```
I'll probe your live site for Next.js vulnerabilities...

[Calls: scan_live(url="https://myapp.vercel.app", scanner="nextjs")]

Scan Results for https://myapp.vercel.app:
✓ Next.js detected (v15.1.0)

⚠️ VULNERABILITY FOUND:
CVE-2025-55128: Next.js Middleware Authentication Bypass
- CVSS: 9.1 (CRITICAL)
- Exploit Difficulty: Easy
- Impact: Authentication can be completely bypassed

Your Next.js version 15.1.0 is vulnerable.

Remediation:
1. Upgrade Next.js to 15.2.0 or later:
   npm install next@latest

2. Restart your application

3. Test authentication flows after upgrade

Would you like me to check for other vulnerabilities?
```

---

### Example 4: List All CVEs

**You:**
```
Show me all critical React CVEs you track
```

**Claude:**
```
[Calls: list_cves(severity="critical", category="react")]

Critical React CVEs (2 found):

| CVE ID | CVSS | Package | Title |
|--------|------|---------|-------|
| CVE-2025-55182 | 10.0 | react@19.0-19.2 | React Server Components RCE |
| CVE-2025-55184 | 9.8 | react-dom@19.x | Client-side XSS via RSC payloads |

Would you like details on any specific CVE?
```

---

### Example 5: Generate Report

**You:**
```
Generate a complete security report for this project
```

**Claude:**
```
I'll generate a comprehensive security report...

[Calls: generate_report(path=".", output_path="security-report.json")]

✅ Security report generated: security-report.json

Summary:
- Total findings: 8
- Critical: 2
- High: 4
- Medium: 2
- Low: 0

Scan coverage:
- React Server Components ✓
- Next.js ✓
- npm packages ✓
- Node.js runtime ✓
- n8n workflows ✓
- Supply chain ✓
- Secrets/credentials ✓

The report includes:
- Detailed CVE information
- CVSS scores and severity
- Remediation steps
- Package locations
- Recommended fixes

Would you like me to open the report and explain the findings?
```

---

## 💚 GitHub Copilot CLI Examples

### Example 1: Suggest Mode

```bash
$ gh copilot suggest "scan current directory for security issues"

Suggestion:
Use shellockolm MCP tool to scan for vulnerabilities:

[Calls: scan_directory(path=".", recursive=true)]

Found 3 CVEs. Run detailed scan? (y/n)
```

### Example 2: Chat Mode

```bash
$ gh copilot chat

> Use shellockolm to check what CVEs are tracked

[Calls: list_cves()]

Shellockolm tracks 32 CVEs across:
- React Server Components (4 CVEs)
- Next.js (6 CVEs)
- Node.js runtime (8 CVEs)
- npm packages (10 CVEs)
- n8n workflow automation (2 CVEs)
- Supply chain attacks (2 CVEs)

Type 'list critical' to see only critical severity.

> list critical

[Calls: list_cves(severity="critical")]

Critical CVEs (8 found):
- CVE-2025-55182 (React RSC RCE)
- CVE-2025-55128 (Next.js auth bypass)
- CVE-2025-55183 (n8n unauth RCE)
...
```

---

## 🔵 Gemini CLI Examples

### Example 1: Basic Scan

```bash
$ gemini chat

> Scan this directory for vulnerabilities using shellockolm

Scanning with shellockolm...

[Calls: scan_directory(path=".", recursive=true)]

Analysis complete. Found:
- 2 critical vulnerabilities
- 3 high-severity issues
- 1 exposed secret

Most urgent: CVE-2025-55182 in React 19.0.0
Recommendation: Upgrade to React 19.3.0 immediately

Show details? (yes/no)
```

---

## ⚫ Cursor IDE Examples

### Example 1: Tag-based

**In Cursor chat:**
```
@shellockolm scan this directory for exploits
```

**Response:**
```
[Calls: scan_directory tool]

Scanning...
Found 4 vulnerabilities in this workspace.

See detailed findings in the security panel.
```

### Example 2: Natural language

**In Cursor chat:**
```
Are there any security issues in my package.json?
```

**Cursor:**
```
Let me check with shellockolm...

[Calls: scan_directory(path=".", scanner="npm")]

Yes, found 2 issues in package.json:
1. jsonpath-plus@7.1.0 has CVE-2025-29927 (malware)
2. mysql2@2.3.3 has CVE-2024-21512 (RCE)

I can help you fix these. Want me to update package.json?
```

---

## 🔧 Continue.dev Examples

### Example 1: Inline Chat

**Select code in VS Code, right-click → Continue:**
```
Check if this React component is vulnerable
```

**Continue:**
```
[Analyzes code + calls scan_directory]

This component uses React 19.0.0 which has:
- CVE-2025-55182 (CRITICAL): RSC RCE vulnerability

Recommend upgrading React or using this safer pattern:
[Shows code suggestion]
```

---

## 🎯 Universal Commands (Work in All Tools)

### Information Queries
```
"What MCP tools do you have?"
"What CVEs does shellockolm track?"
"What scanners are available?"
"Explain CVE-2025-55182"
```

### Scanning
```
"Scan this project"
"Check for vulnerabilities"
"Find security issues in my React app"
"Scan [specific directory path]"
```

### Live Testing
```
"Is [URL] vulnerable?"
"Check if [URL] is hackable"
"Test [URL] for exploits"
```

### Filtering
```
"Show only critical CVEs"
"List React vulnerabilities"
"What Next.js CVEs are tracked?"
```

### Reporting
```
"Generate security report"
"Create detailed findings report"
"Export vulnerabilities as JSON"
```

---

## 💡 Pro Tips

### 1. Be Specific About Paths
❌ *"Scan my project"* (AI doesn't know which one)  
✅ *"Scan G:\myproject for vulnerabilities"*  
✅ *"Scan /home/user/myapp for CVEs"*

### 2. Ask for Context
✅ *"What is CVE-2025-55182 and am I affected?"*  
Instead of just: *"What is CVE-2025-55182?"*

### 3. Chain Commands
✅ *"Scan this project, then show only critical issues"*  
✅ *"Check if I'm vulnerable to CVE-2025-55182, and if so, help me fix it"*

### 4. Use Filters
✅ *"Show React CVEs with CVSS > 9"*  
✅ *"List all vulnerabilities in Next.js"*

### 5. Request Actions
✅ *"Generate a report and explain the top 3 issues"*  
✅ *"Scan, prioritize by severity, and suggest fixes"*

---

## 🚨 Common Pitfalls

### ❌ Saying "scan" without a path
AI might not know what to scan.

**Better:**
```
"Scan the current working directory"
"Scan G:\myproject"
```

### ❌ Expecting AI to fix code automatically
MCP provides detection, not code modification (yet).

**Better:**
```
"Show me how to fix CVE-2025-55182"
"What's the remediation for this vulnerability?"
```

### ❌ Testing without MCP configured
If MCP isn't set up, AI can't use the tools.

**Verify first:**
```
"What MCP tools do you have access to?"
```

---

**More Examples:** See [MCP_SETUP.md](MCP_SETUP.md) for troubleshooting and advanced usage.

**Built with 🔍 by @hlsitechio & AI (Claude + GitHub Copilot)**
