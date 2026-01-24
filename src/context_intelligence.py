#!/usr/bin/env python3
"""
Context Intelligence for Shellockolm
Smart path detection and actionable remediation commands
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class PathContext(Enum):
    """Type of path/project context"""
    EXPLOIT_DATA = "exploit_data"          # Metasploit, exploit-db, etc. (intentionally vuln)
    RESEARCH = "research"                   # Research/archive folders
    NODE_MODULES = "node_modules"           # Dependencies (use npm audit)
    TEST_FIXTURES = "test_fixtures"         # Test data (not production)
    ARCHIVE = "archive"                     # Archived/backup code
    VENDOR = "vendor"                       # Third-party vendor code
    PRODUCTION = "production"               # Actual project code


@dataclass
class FindingContext:
    """Context information for a vulnerability finding"""
    path_type: PathContext
    is_actionable: bool
    priority: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    message: str
    fix_command: Optional[str] = None
    skip_reason: Optional[str] = None


# Patterns to detect path contexts
CONTEXT_PATTERNS = {
    PathContext.EXPLOIT_DATA: [
        r"metasploit[-_]?framework",
        r"exploit[-_]?db",
        r"/exploits?/",
        r"/payloads?/",
        r"poc[-_]?",
        r"proof[-_]?of[-_]?concept",
        r"cve[-_]\d{4}[-_]\d+",  # CVE-specific folders
    ],
    PathContext.RESEARCH: [
        r"/research/",
        r"/investigation/",
        r"/analysis/",
        r"/samples?/",
        r"/hackerone/programs/",
        r"/bugcrowd/",
    ],
    PathContext.NODE_MODULES: [
        r"/node_modules/",
    ],
    PathContext.TEST_FIXTURES: [
        r"/test[-_]?fixtures?/",
        r"/__tests__/",
        r"/test[-_]?data/",
        r"\.test\.",
        r"\.spec\.",
    ],
    PathContext.ARCHIVE: [
        r"/archive/",
        r"/backup/",
        r"/old/",
        r"/deprecated/",
        r"\.bak",
    ],
    PathContext.VENDOR: [
        r"/vendor/",
        r"/third[-_]?party/",
        r"/external/",
    ],
}


def detect_path_context(file_path: str) -> PathContext:
    """
    Detect the context type of a file path
    Returns the most specific context found
    """
    path_lower = file_path.lower()

    # Check patterns in order of specificity
    for context, patterns in CONTEXT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, path_lower):
                return context

    return PathContext.PRODUCTION


def get_fix_command(package: str, current_version: str, fixed_version: str,
                    file_path: str, vuln_type: str = "npm") -> Optional[str]:
    """
    Generate actionable fix command based on vulnerability type
    """
    project_dir = str(Path(file_path).parent)

    # Node.js runtime vulnerabilities
    if package.lower() == "node" or package.lower() == "nodejs":
        return f"""
# Option 1: Using nvm (recommended)
nvm install {fixed_version}
nvm use {fixed_version}

# Option 2: Using apt (Debian/Ubuntu)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Option 3: Direct download from nodejs.org
# https://nodejs.org/en/download/
"""

    # npm packages
    if vuln_type in ["npm", "npm_packages", "react", "nextjs"]:
        if fixed_version and fixed_version != "See remediation":
            return f"cd {project_dir} && npm install {package}@{fixed_version}"
        else:
            return f"cd {project_dir} && npm audit fix"

    # Yarn
    if "yarn.lock" in file_path:
        if fixed_version:
            return f"cd {project_dir} && yarn upgrade {package}@{fixed_version}"
        else:
            return f"cd {project_dir} && yarn audit fix"

    return None


def analyze_finding(file_path: str, package: str, current_version: str,
                    fixed_version: str, severity: str, cve_id: str,
                    vuln_type: str = "npm") -> FindingContext:
    """
    Analyze a vulnerability finding and return context with actionable advice
    """
    context = detect_path_context(file_path)

    # Exploit data - intentionally vulnerable
    if context == PathContext.EXPLOIT_DATA:
        return FindingContext(
            path_type=context,
            is_actionable=False,
            priority="INFO",
            message=f"[dim]Exploit/PoC data - intentionally vulnerable[/dim]",
            skip_reason="This is Metasploit/exploit data meant to be vulnerable",
            fix_command=None
        )

    # Research folders
    if context == PathContext.RESEARCH:
        return FindingContext(
            path_type=context,
            is_actionable=False,
            priority="LOW",
            message=f"[dim]Research/sample folder - not production code[/dim]",
            skip_reason="This is a research sample, not your actual code",
            fix_command=None
        )

    # Archive
    if context == PathContext.ARCHIVE:
        return FindingContext(
            path_type=context,
            is_actionable=False,
            priority="LOW",
            message=f"[dim]Archived code - consider removing if unused[/dim]",
            skip_reason="This is archived code",
            fix_command=None
        )

    # node_modules
    if context == PathContext.NODE_MODULES:
        project_dir = str(Path(file_path).parent).split("/node_modules")[0]
        return FindingContext(
            path_type=context,
            is_actionable=True,
            priority=severity,
            message=f"Dependency vulnerability",
            fix_command=f"cd {project_dir} && npm audit fix"
        )

    # Test fixtures
    if context == PathContext.TEST_FIXTURES:
        return FindingContext(
            path_type=context,
            is_actionable=False,
            priority="LOW",
            message=f"[dim]Test fixture - not deployed code[/dim]",
            skip_reason="This is test data only",
            fix_command=None
        )

    # Vendor
    if context == PathContext.VENDOR:
        return FindingContext(
            path_type=context,
            is_actionable=True,
            priority=severity,
            message=f"Third-party code - check for updates from vendor",
            fix_command=None
        )

    # Production code - full actionability
    fix_cmd = get_fix_command(package, current_version, fixed_version, file_path, vuln_type)

    return FindingContext(
        path_type=context,
        is_actionable=True,
        priority=severity,
        message=f"[bold]Production code - ACTION REQUIRED[/bold]",
        fix_command=fix_cmd
    )


def get_quick_fix_summary(findings: List[Dict]) -> Dict[str, List[str]]:
    """
    Generate a summary of quick fix commands grouped by action
    """
    fixes = {
        "npm_update": [],      # npm install package@version
        "npm_audit": [],       # npm audit fix
        "node_upgrade": [],    # Node.js upgrade
        "manual": [],          # Manual intervention needed
        "skip": [],            # Can be skipped (exploit data, etc.)
    }

    seen_commands = set()

    for finding in findings:
        file_path = finding.get("file_path", "")
        package = finding.get("package", "")
        version = finding.get("version", "")
        fixed_version = finding.get("patched_version", "")
        severity = finding.get("severity", "MEDIUM")
        cve_id = finding.get("cve_id", "")

        ctx = analyze_finding(file_path, package, version, fixed_version, severity, cve_id)

        if not ctx.is_actionable:
            if ctx.skip_reason and ctx.skip_reason not in fixes["skip"]:
                fixes["skip"].append(f"{cve_id}: {ctx.skip_reason}")
            continue

        if ctx.fix_command:
            cmd = ctx.fix_command.strip()
            if "nvm install" in cmd or "apt-get install" in cmd:
                if cmd not in seen_commands:
                    fixes["node_upgrade"].append(cmd)
                    seen_commands.add(cmd)
            elif "npm install" in cmd:
                if cmd not in seen_commands:
                    fixes["npm_update"].append(cmd)
                    seen_commands.add(cmd)
            elif "npm audit" in cmd:
                project_dir = cmd.split("cd ")[1].split(" &&")[0] if "cd " in cmd else "."
                if project_dir not in seen_commands:
                    fixes["npm_audit"].append(f"cd {project_dir} && npm audit fix")
                    seen_commands.add(project_dir)

    return fixes


def format_actionable_tips(findings: List[Dict]) -> str:
    """
    Format findings into actionable tips for the user
    """
    fixes = get_quick_fix_summary(findings)

    output = []

    # Critical fixes first
    if fixes["npm_update"]:
        output.append("\n[bold cyan]Quick Fix Commands:[/bold cyan]")
        for cmd in fixes["npm_update"][:5]:  # Limit to top 5
            output.append(f"  [green]$[/green] {cmd}")

    if fixes["npm_audit"]:
        output.append("\n[bold cyan]Run npm audit fix in these projects:[/bold cyan]")
        for cmd in fixes["npm_audit"][:5]:
            output.append(f"  [green]$[/green] {cmd}")

    if fixes["node_upgrade"]:
        output.append("\n[bold yellow]Node.js Upgrade Required:[/bold yellow]")
        output.append("  [green]$[/green] nvm install 20.20.0 && nvm use 20.20.0")
        output.append("  [dim]Or visit: https://nodejs.org/en/download/[/dim]")

    if fixes["skip"]:
        output.append(f"\n[dim]Skipped {len(fixes['skip'])} findings (exploit data, research, etc.)[/dim]")

    return "\n".join(output)


# Test when run directly
if __name__ == "__main__":
    # Test paths
    test_paths = [
        "/metasploit-framework/data/exploits/cve_2025_55182/package.json",
        "/home/user/myproject/package.json",
        "/research/hackerone/programs/coinbase/test/package.json",
        "/archive/old_project/package.json",
        "/app/node_modules/lodash/package.json",
    ]

    for path in test_paths:
        ctx = detect_path_context(path)
        print(f"{path}")
        print(f"  Context: {ctx.value}")
        print()
