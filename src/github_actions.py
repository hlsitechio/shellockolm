#!/usr/bin/env python3
"""
GitHub Actions Workflow Generator for Shellockolm
Creates CI/CD workflows for automated security scanning
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich import box
except ImportError:
    pass


class TriggerType(Enum):
    """Types of workflow triggers"""
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    SCHEDULE = "schedule"
    WORKFLOW_DISPATCH = "workflow_dispatch"


class ScanLevel(Enum):
    """Scanning intensity levels"""
    BASIC = "basic"  # Quick scan, critical issues only
    STANDARD = "standard"  # Default scan
    COMPREHENSIVE = "comprehensive"  # All scanners, all checks


@dataclass
class WorkflowConfig:
    """Configuration for workflow generation"""
    name: str = "Shellockolm Security Scan"
    triggers: List[TriggerType] = field(default_factory=lambda: [TriggerType.PUSH, TriggerType.PULL_REQUEST])
    branches: List[str] = field(default_factory=lambda: ["main", "master", "develop"])
    scan_level: ScanLevel = ScanLevel.STANDARD
    fail_on_critical: bool = True
    fail_on_high: bool = False
    upload_sarif: bool = True
    create_issues: bool = False
    schedule_cron: str = "0 6 * * 1"  # Monday 6am
    python_version: str = "3.11"
    node_version: str = "20"
    cache_dependencies: bool = True


class GitHubActionsGenerator:
    """
    Generates GitHub Actions workflows for automated security scanning
    """

    WORKFLOW_DIR = ".github/workflows"

    def __init__(self, console: Optional[Console] = None):
        self.console = console

    def generate_workflow(self, config: WorkflowConfig) -> str:
        """Generate a complete GitHub Actions workflow YAML"""
        workflow = {
            "name": config.name,
            "on": self._generate_triggers(config),
            "permissions": {
                "contents": "read",
                "security-events": "write" if config.upload_sarif else "none",
                "issues": "write" if config.create_issues else "none",
            },
            "jobs": {
                "security-scan": self._generate_scan_job(config)
            }
        }

        # Convert to YAML manually to ensure proper formatting
        return self._to_yaml(workflow)

    def _generate_triggers(self, config: WorkflowConfig) -> Dict:
        """Generate workflow triggers"""
        triggers = {}

        for trigger in config.triggers:
            if trigger == TriggerType.PUSH:
                triggers["push"] = {
                    "branches": config.branches,
                    "paths": [
                        "package.json",
                        "package-lock.json",
                        "yarn.lock",
                        "**/*.js",
                        "**/*.ts",
                        "**/*.jsx",
                        "**/*.tsx",
                    ]
                }
            elif trigger == TriggerType.PULL_REQUEST:
                triggers["pull_request"] = {
                    "branches": config.branches
                }
            elif trigger == TriggerType.SCHEDULE:
                triggers["schedule"] = [
                    {"cron": config.schedule_cron}
                ]
            elif trigger == TriggerType.WORKFLOW_DISPATCH:
                triggers["workflow_dispatch"] = {
                    "inputs": {
                        "scan_level": {
                            "description": "Scan intensity level",
                            "required": False,
                            "default": "standard",
                            "type": "choice",
                            "options": ["basic", "standard", "comprehensive"]
                        }
                    }
                }

        return triggers

    def _generate_scan_job(self, config: WorkflowConfig) -> Dict:
        """Generate the main scanning job"""
        steps = []

        # Checkout
        steps.append({
            "name": "Checkout repository",
            "uses": "actions/checkout@v4",
            "with": {"fetch-depth": 0}
        })

        # Setup Python
        steps.append({
            "name": "Set up Python",
            "uses": "actions/setup-python@v5",
            "with": {"python-version": config.python_version}
        })

        # Setup Node (for npm audit)
        steps.append({
            "name": "Set up Node.js",
            "uses": "actions/setup-node@v4",
            "with": {"node-version": config.node_version}
        })

        # Cache pip
        if config.cache_dependencies:
            steps.append({
                "name": "Cache pip dependencies",
                "uses": "actions/cache@v4",
                "with": {
                    "path": "~/.cache/pip",
                    "key": "${{ runner.os }}-pip-shellockolm",
                    "restore-keys": "${{ runner.os }}-pip-"
                }
            })

        # Install Shellockolm
        steps.append({
            "name": "Install Shellockolm",
            "run": "pip install shellockolm"
        })

        # Install project dependencies (for npm audit)
        steps.append({
            "name": "Install npm dependencies",
            "run": "npm ci --ignore-scripts",
            "continue-on-error": True
        })

        # Run scan based on level
        scan_cmd = self._get_scan_command(config)
        steps.append({
            "name": "Run security scan",
            "id": "security-scan",
            "run": scan_cmd,
            "continue-on-error": True
        })

        # Generate SARIF report
        if config.upload_sarif:
            steps.append({
                "name": "Generate SARIF report",
                "run": "shellockolm sarif-export . --output security-results.sarif",
                "continue-on-error": True
            })

            steps.append({
                "name": "Upload SARIF to GitHub Security",
                "uses": "github/codeql-action/upload-sarif@v3",
                "with": {
                    "sarif_file": "security-results.sarif"
                },
                "if": "always()"
            })

        # Create issues for critical findings
        if config.create_issues:
            steps.append({
                "name": "Create issues for critical findings",
                "if": "steps.security-scan.outputs.critical_count > 0",
                "uses": "actions/github-script@v7",
                "with": {
                    "script": self._get_issue_script()
                }
            })

        # Check failure conditions
        fail_conditions = []
        if config.fail_on_critical:
            fail_conditions.append("steps.security-scan.outputs.critical_count > 0")
        if config.fail_on_high:
            fail_conditions.append("steps.security-scan.outputs.high_count > 0")

        if fail_conditions:
            steps.append({
                "name": "Check scan results",
                "if": " || ".join(fail_conditions),
                "run": "echo 'Security vulnerabilities found!' && exit 1"
            })

        return {
            "runs-on": "ubuntu-latest",
            "steps": steps
        }

    def _get_scan_command(self, config: WorkflowConfig) -> str:
        """Get the scan command based on level"""
        base_cmd = "shellockolm scan ."

        if config.scan_level == ScanLevel.BASIC:
            return f"{base_cmd} --fast --severity critical"
        elif config.scan_level == ScanLevel.COMPREHENSIVE:
            return f"{base_cmd} --deep --all-scanners"
        else:
            return base_cmd

    def _get_issue_script(self) -> str:
        """Get the script for creating GitHub issues"""
        return '''
const fs = require('fs');
const results = JSON.parse(fs.readFileSync('security-results.json', 'utf8'));

for (const finding of results.critical) {
  await github.rest.issues.create({
    owner: context.repo.owner,
    repo: context.repo.repo,
    title: `[Security] ${finding.cve_id}: ${finding.title}`,
    body: `## Security Vulnerability Detected

**CVE:** ${finding.cve_id}
**Severity:** CRITICAL
**Package:** ${finding.package}
**Version:** ${finding.version}

### Description
${finding.description}

### Recommendation
${finding.recommendation}

---
*This issue was automatically created by Shellockolm Security Scanner*`,
    labels: ['security', 'critical', 'automated']
  });
}
'''

    def _to_yaml(self, data: Dict, indent: int = 0) -> str:
        """Convert dictionary to YAML string"""
        lines = []
        indent_str = "  " * indent

        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{indent_str}{key}:")
                lines.append(self._to_yaml(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{indent_str}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        # First item on same line as dash
                        first = True
                        for k, v in item.items():
                            if first:
                                if isinstance(v, dict):
                                    lines.append(f"{indent_str}  - {k}:")
                                    lines.append(self._to_yaml(v, indent + 3))
                                elif isinstance(v, list):
                                    lines.append(f"{indent_str}  - {k}:")
                                    for subitem in v:
                                        lines.append(f"{indent_str}      - {subitem}")
                                else:
                                    lines.append(f"{indent_str}  - {k}: {self._format_value(v)}")
                                first = False
                            else:
                                if isinstance(v, dict):
                                    lines.append(f"{indent_str}    {k}:")
                                    lines.append(self._to_yaml(v, indent + 3))
                                elif isinstance(v, list):
                                    lines.append(f"{indent_str}    {k}:")
                                    for subitem in v:
                                        lines.append(f"{indent_str}      - {subitem}")
                                else:
                                    lines.append(f"{indent_str}    {k}: {self._format_value(v)}")
                    else:
                        lines.append(f"{indent_str}  - {self._format_value(item)}")
            elif isinstance(value, bool):
                lines.append(f"{indent_str}{key}: {str(value).lower()}")
            elif isinstance(value, str) and ("\n" in value or value.startswith("'")):
                lines.append(f"{indent_str}{key}: |")
                for line in value.split("\n"):
                    lines.append(f"{indent_str}  {line}")
            else:
                lines.append(f"{indent_str}{key}: {self._format_value(value)}")

        return "\n".join(lines)

    def _format_value(self, value: Any) -> str:
        """Format a single value for YAML"""
        if isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, str):
            if any(c in value for c in [':', '#', '{', '}', '[', ']', ',', '&', '*', '?', '|', '-', '<', '>', '=', '!', '%', '@', '`']):
                return f'"{value}"'
            if value.startswith('${{'):
                return value
            return value
        return str(value)

    def create_workflow_file(self, project_path: str, config: Optional[WorkflowConfig] = None) -> str:
        """Create the workflow file in the project"""
        config = config or WorkflowConfig()
        project = Path(project_path)

        # Create .github/workflows directory
        workflow_dir = project / self.WORKFLOW_DIR
        workflow_dir.mkdir(parents=True, exist_ok=True)

        # Generate workflow
        workflow_content = self.generate_workflow(config)

        # Write file
        workflow_path = workflow_dir / "shellockolm-security.yml"
        with open(workflow_path, "w") as f:
            f.write(workflow_content)

        return str(workflow_path)

    def generate_basic_workflow(self) -> str:
        """Generate a minimal workflow for quick setup"""
        return '''name: Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Shellockolm
        run: pip install shellockolm

      - name: Run security scan
        run: shellockolm scan .

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-results.sarif
        if: always()
'''

    def generate_comprehensive_workflow(self) -> str:
        """Generate a full-featured workflow"""
        return '''name: Comprehensive Security Scan

on:
  push:
    branches: [main, master, develop]
    paths:
      - 'package.json'
      - 'package-lock.json'
      - 'yarn.lock'
      - '**/*.js'
      - '**/*.ts'
  pull_request:
    branches: [main, master]
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday
  workflow_dispatch:
    inputs:
      scan_level:
        description: 'Scan intensity'
        required: false
        default: 'standard'
        type: choice
        options:
          - basic
          - standard
          - comprehensive

permissions:
  contents: read
  security-events: write
  issues: write

jobs:
  security-scan:
    runs-on: ubuntu-latest
    outputs:
      critical_count: ${{ steps.scan.outputs.critical }}
      high_count: ${{ steps.scan.outputs.high }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Cache dependencies
        uses: actions/cache@v4
        with:
          path: |
            ~/.cache/pip
            ~/.npm
          key: ${{ runner.os }}-deps-${{ hashFiles('**/package-lock.json') }}

      - name: Install Shellockolm
        run: pip install shellockolm typer rich

      - name: Install npm dependencies
        run: npm ci --ignore-scripts || true

      - name: Run full scan
        id: scan
        run: |
          shellockolm scan . --output json > scan-results.json
          echo "critical=$(jq '.summary.critical // 0' scan-results.json)" >> $GITHUB_OUTPUT
          echo "high=$(jq '.summary.high // 0' scan-results.json)" >> $GITHUB_OUTPUT
        continue-on-error: true

      - name: Run npm audit
        run: shellockolm npm-audit .
        continue-on-error: true

      - name: Check GitHub Advisory
        run: shellockolm ghsa-scan .
        continue-on-error: true

      - name: Generate SBOM
        run: shellockolm sbom-generate .
        continue-on-error: true

      - name: Generate SARIF report
        run: shellockolm sarif-export . --output security-results.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security-results.sarif
        if: always()

      - name: Upload scan artifacts
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: |
            scan-results.json
            sbom/
            security-results.sarif
        if: always()

      - name: Fail on critical vulnerabilities
        if: steps.scan.outputs.critical > 0
        run: |
          echo "::error::Found ${{ steps.scan.outputs.critical }} critical vulnerabilities!"
          exit 1

  notify:
    needs: security-scan
    runs-on: ubuntu-latest
    if: failure()
    steps:
      - name: Create issue for failures
        uses: actions/github-script@v7
        with:
          script: |
            const title = 'Security vulnerabilities detected';
            const body = `## Security Scan Failed

            The automated security scan detected vulnerabilities that need attention.

            - **Critical:** ${{ needs.security-scan.outputs.critical_count }}
            - **High:** ${{ needs.security-scan.outputs.high_count }}

            Please review the [workflow run](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}) for details.

            ---
            *Automated by Shellockolm Security Scanner*`;

            await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: title,
              body: body,
              labels: ['security', 'automated']
            });
'''

    def preview_workflow(self, workflow_content: str):
        """Display workflow preview with syntax highlighting"""
        if self.console:
            syntax = Syntax(workflow_content, "yaml", theme="monokai", line_numbers=True)
            self.console.print(Panel(syntax, title="GitHub Actions Workflow", border_style="bright_cyan"))


def create_workflow(project_path: str, level: str = "standard") -> str:
    """Helper function to create a workflow"""
    generator = GitHubActionsGenerator()

    config = WorkflowConfig()
    if level == "basic":
        config.scan_level = ScanLevel.BASIC
        config.upload_sarif = False
    elif level == "comprehensive":
        config.scan_level = ScanLevel.COMPREHENSIVE
        config.triggers = [TriggerType.PUSH, TriggerType.PULL_REQUEST, TriggerType.SCHEDULE, TriggerType.WORKFLOW_DISPATCH]

    return generator.create_workflow_file(project_path, config)


# CLI interface for standalone testing
if __name__ == "__main__":
    import sys

    console = Console()
    generator = GitHubActionsGenerator(console)

    if len(sys.argv) > 1:
        project = sys.argv[1]
        level = sys.argv[2] if len(sys.argv) > 2 else "standard"

        path = create_workflow(project, level)
        console.print(f"[green]Created workflow: {path}[/green]")
    else:
        # Preview comprehensive workflow
        console.print("[bold]Comprehensive Workflow Preview:[/bold]\n")
        generator.preview_workflow(generator.generate_comprehensive_workflow())
