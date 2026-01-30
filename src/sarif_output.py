#!/usr/bin/env python3
"""
Shellockolm SARIF Output Generator
Generates SARIF (Static Analysis Results Interchange Format) reports
for integration with GitHub Code Scanning, VS Code, and CI/CD pipelines

SARIF Spec: https://sarifweb.azurewebsites.net/
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# SARIF version we generate
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


@dataclass
class SarifRule:
    """A SARIF rule (vulnerability definition)"""
    id: str
    name: str
    short_description: str
    full_description: str
    help_uri: str
    security_severity: str  # "critical", "high", "medium", "low", "note"
    tags: List[str] = field(default_factory=list)
    
    def to_sarif(self) -> Dict[str, Any]:
        """Convert to SARIF rule format"""
        # Map severity to SARIF level
        severity_map = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }
        level = severity_map.get(self.security_severity.lower(), "warning")
        
        # Security severity score (0-10)
        severity_scores = {
            "critical": "9.8",
            "high": "8.0",
            "medium": "5.0",
            "low": "2.0",
            "info": "0.0",
        }
        score = severity_scores.get(self.security_severity.lower(), "5.0")
        
        return {
            "id": self.id,
            "name": self.name,
            "shortDescription": {
                "text": self.short_description
            },
            "fullDescription": {
                "text": self.full_description
            },
            "helpUri": self.help_uri,
            "defaultConfiguration": {
                "level": level
            },
            "properties": {
                "security-severity": score,
                "tags": self.tags
            }
        }


@dataclass
class SarifResult:
    """A SARIF result (finding instance)"""
    rule_id: str
    message: str
    file_path: str
    start_line: int
    start_column: int = 1
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    level: str = "warning"  # "error", "warning", "note"
    fingerprint: Optional[str] = None
    
    def to_sarif(self, base_path: str = "") -> Dict[str, Any]:
        """Convert to SARIF result format"""
        # Calculate fingerprint for deduplication
        if not self.fingerprint:
            fp_data = f"{self.rule_id}:{self.file_path}:{self.start_line}:{self.message}"
            self.fingerprint = hashlib.sha256(fp_data.encode()).hexdigest()[:16]
        
        # Build location
        physical_location = {
            "artifactLocation": {
                "uri": self.file_path,
                "uriBaseId": "%SRCROOT%"
            },
            "region": {
                "startLine": self.start_line,
                "startColumn": self.start_column,
            }
        }
        
        if self.end_line:
            physical_location["region"]["endLine"] = self.end_line
        if self.end_column:
            physical_location["region"]["endColumn"] = self.end_column
        
        return {
            "ruleId": self.rule_id,
            "level": self.level,
            "message": {
                "text": self.message
            },
            "locations": [{
                "physicalLocation": physical_location
            }],
            "fingerprints": {
                "primary": self.fingerprint
            }
        }


class SarifGenerator:
    """
    Generates SARIF reports from Shellockolm scan results
    """
    
    TOOL_NAME = "shellockolm"
    TOOL_VERSION = "2.0.0"
    TOOL_INFO_URI = "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner"
    
    def __init__(self):
        self.rules: Dict[str, SarifRule] = {}
        self.results: List[SarifResult] = []
        self._init_builtin_rules()
    
    def _init_builtin_rules(self):
        """Initialize built-in security rules"""
        # CVE rules
        cve_rules = [
            SarifRule(
                id="CVE-2025-29927",
                name="Next.js Middleware Bypass",
                short_description="Next.js middleware authorization bypass",
                full_description="Critical authorization bypass in Next.js middleware via x-middleware-subrequest header",
                help_uri="https://nvd.nist.gov/vuln/detail/CVE-2025-29927",
                security_severity="critical",
                tags=["security", "vulnerability", "cve", "nextjs"]
            ),
            SarifRule(
                id="CVE-2025-55182",
                name="React Server RCE",
                short_description="React Server Components RCE via registerServerReference",
                full_description="Remote code execution in React Server Components through arbitrary function registration",
                help_uri="https://nvd.nist.gov/vuln/detail/CVE-2025-55182",
                security_severity="critical",
                tags=["security", "vulnerability", "cve", "react", "rce"]
            ),
            SarifRule(
                id="CVE-2026-21858",
                name="n8n Unauthenticated RCE",
                short_description="n8n Ni8mare unauthenticated RCE",
                full_description="Unauthenticated RCE in n8n workflow automation via Form Webhooks Content-Type confusion",
                help_uri="https://nvd.nist.gov/vuln/detail/CVE-2026-21858",
                security_severity="critical",
                tags=["security", "vulnerability", "cve", "n8n", "rce"]
            ),
        ]
        
        # Malware rules
        malware_rules = [
            SarifRule(
                id="MALWARE-RCE-001",
                name="Remote Code Execution Pattern",
                short_description="Code execution pattern detected",
                full_description="Detected code pattern that could lead to remote code execution (eval, exec, etc.)",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#malware-patterns",
                security_severity="critical",
                tags=["security", "malware", "rce"]
            ),
            SarifRule(
                id="MALWARE-EXFIL-001",
                name="Data Exfiltration Pattern",
                short_description="Data exfiltration pattern detected",
                full_description="Detected code pattern that could exfiltrate sensitive data",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#malware-patterns",
                security_severity="high",
                tags=["security", "malware", "exfiltration"]
            ),
            SarifRule(
                id="MALWARE-BACKDOOR-001",
                name="Backdoor Pattern",
                short_description="Backdoor pattern detected",
                full_description="Detected code pattern that could be a backdoor",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#malware-patterns",
                security_severity="critical",
                tags=["security", "malware", "backdoor"]
            ),
        ]
        
        # Secret rules
        secret_rules = [
            SarifRule(
                id="SECRET-AWS-001",
                name="AWS Credentials Exposed",
                short_description="AWS credentials found in code",
                full_description="Hardcoded AWS access keys or secrets detected in source code",
                help_uri="https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html",
                security_severity="critical",
                tags=["security", "secrets", "aws", "credential"]
            ),
            SarifRule(
                id="SECRET-API-001",
                name="API Key Exposed",
                short_description="API key found in code",
                full_description="Hardcoded API key or token detected in source code",
                help_uri="https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
                security_severity="high",
                tags=["security", "secrets", "api-key"]
            ),
            SarifRule(
                id="SECRET-GENERIC-001",
                name="Generic Secret Exposed",
                short_description="Potential secret found in code",
                full_description="High entropy string detected that may be a secret or credential",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#secrets-scanner",
                security_severity="medium",
                tags=["security", "secrets"]
            ),
        ]
        
        # Dependency rules
        dependency_rules = [
            SarifRule(
                id="DEP-TYPOSQUAT-001",
                name="Typosquatting Package",
                short_description="Potential typosquatting package detected",
                full_description="Package name appears to be a typosquat of a legitimate package",
                help_uri="https://snyk.io/blog/typosquatting-attacks/",
                security_severity="critical",
                tags=["security", "supply-chain", "typosquatting"]
            ),
            SarifRule(
                id="DEP-VULN-001",
                name="Vulnerable Dependency",
                short_description="Vulnerable dependency version",
                full_description="Dependency has known security vulnerabilities",
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#vulnerability-scanner",
                security_severity="high",
                tags=["security", "dependency", "vulnerability"]
            ),
        ]
        
        # Add all rules
        for rule in cve_rules + malware_rules + secret_rules + dependency_rules:
            self.rules[rule.id] = rule
    
    def add_rule(self, rule: SarifRule):
        """Add a custom rule"""
        self.rules[rule.id] = rule
    
    def add_result(self, result: SarifResult):
        """Add a result (finding)"""
        self.results.append(result)
    
    def add_cve_finding(self, cve_id: str, file_path: str, line_number: int,
                       message: str, severity: str = "high"):
        """Add a CVE finding"""
        # Ensure we have a rule for this CVE
        if cve_id not in self.rules:
            self.add_rule(SarifRule(
                id=cve_id,
                name=f"{cve_id} Vulnerability",
                short_description=message[:100],
                full_description=message,
                help_uri=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                security_severity=severity,
                tags=["security", "vulnerability", "cve"]
            ))
        
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        level = level_map.get(severity.lower(), "warning")
        
        self.add_result(SarifResult(
            rule_id=cve_id,
            message=message,
            file_path=file_path,
            start_line=line_number,
            level=level
        ))
    
    def add_malware_finding(self, pattern_id: str, pattern_name: str, file_path: str,
                           line_number: int, message: str, severity: str = "high"):
        """Add a malware pattern finding"""
        rule_id = f"MALWARE-{pattern_id}"
        
        if rule_id not in self.rules:
            self.add_rule(SarifRule(
                id=rule_id,
                name=pattern_name,
                short_description=pattern_name,
                full_description=message,
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#malware-patterns",
                security_severity=severity,
                tags=["security", "malware"]
            ))
        
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        level = level_map.get(severity.lower(), "warning")
        
        self.add_result(SarifResult(
            rule_id=rule_id,
            message=message,
            file_path=file_path,
            start_line=line_number,
            level=level
        ))
    
    def add_secret_finding(self, secret_type: str, file_path: str, line_number: int,
                          message: str, severity: str = "high"):
        """Add a secret finding"""
        rule_id = f"SECRET-{secret_type.upper()}"
        
        if rule_id not in self.rules:
            self.add_rule(SarifRule(
                id=rule_id,
                name=f"{secret_type} Exposed",
                short_description=f"Exposed {secret_type}",
                full_description=message,
                help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#secrets-scanner",
                security_severity=severity,
                tags=["security", "secrets", secret_type.lower()]
            ))
        
        level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        level = level_map.get(severity.lower(), "warning")
        
        self.add_result(SarifResult(
            rule_id=rule_id,
            message=message,
            file_path=file_path,
            start_line=line_number,
            level=level
        ))
    
    def generate(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate complete SARIF report"""
        # Build tool section
        tool = {
            "driver": {
                "name": self.TOOL_NAME,
                "version": self.TOOL_VERSION,
                "informationUri": self.TOOL_INFO_URI,
                "rules": [rule.to_sarif() for rule in self.rules.values()]
            }
        }
        
        # Build run section
        run = {
            "tool": tool,
            "results": [result.to_sarif() for result in self.results],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }
        
        # Build complete SARIF document
        sarif = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run]
        }
        
        # Write to file if path provided
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(sarif, f, indent=2)
        
        return sarif
    
    def from_scan_results(self, results: List[Any], base_path: str = ""):
        """Import results from Shellockolm scan"""
        for result in results:
            # Handle ScanFinding objects
            if hasattr(result, 'cve_id'):
                self.add_cve_finding(
                    cve_id=result.cve_id,
                    file_path=result.file_path,
                    line_number=getattr(result, 'line_number', 1),
                    message=f"{result.title}: {result.description[:200]}",
                    severity=result.severity.value if hasattr(result.severity, 'value') else str(result.severity)
                )
    
    def from_malware_report(self, report: Any):
        """Import results from MalwareAnalyzer report"""
        for match in report.matches:
            severity = match.threat_level.value if hasattr(match.threat_level, 'value') else str(match.threat_level)
            malware_type = match.malware_type.value if hasattr(match.malware_type, 'value') else str(match.malware_type)
            
            self.add_malware_finding(
                pattern_id=match.pattern_id,
                pattern_name=match.pattern_name,
                file_path=match.file_path,
                line_number=match.line_number,
                message=f"{match.pattern_name}: {match.explanation}",
                severity=severity
            )
    
    def from_secrets_report(self, report: Any):
        """Import results from SecretsScanner report"""
        for match in report.matches:
            severity = match.pattern.severity.value if hasattr(match.pattern.severity, 'value') else str(match.pattern.severity)
            secret_type = match.pattern.secret_type.value if hasattr(match.pattern.secret_type, 'value') else str(match.pattern.secret_type)
            
            self.add_secret_finding(
                secret_type=secret_type,
                file_path=match.file_path,
                line_number=match.line_number,
                message=f"{match.pattern.name}: {match.pattern.description}",
                severity=severity
            )
    
    def from_lockfile_report(self, report: Any):
        """Import results from LockfileAnalyzer report"""
        for issue in report.issues:
            rule_id = f"DEP-{issue.issue_type.value.upper()}"
            severity = issue.severity.value if hasattr(issue.severity, 'value') else str(issue.severity)
            
            if rule_id not in self.rules:
                self.add_rule(SarifRule(
                    id=rule_id,
                    name=issue.title[:50],
                    short_description=issue.title,
                    full_description=issue.description,
                    help_uri="https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner#lockfile-analyzer",
                    security_severity=severity,
                    tags=["security", "dependency", issue.issue_type.value]
                ))
            
            level_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
            level = level_map.get(severity.lower(), "warning")
            
            self.add_result(SarifResult(
                rule_id=rule_id,
                message=f"{issue.title}: {issue.description}",
                file_path=report.file_path,
                start_line=issue.line_number or 1,
                level=level
            ))


# ─────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for testing"""
    import sys
    
    generator = SarifGenerator()
    
    # Add some test findings
    generator.add_cve_finding(
        cve_id="CVE-2025-29927",
        file_path="middleware.ts",
        line_number=15,
        message="Next.js middleware bypass vulnerability detected",
        severity="critical"
    )
    
    generator.add_secret_finding(
        secret_type="AWS_KEY",
        file_path="config.js",
        line_number=42,
        message="AWS access key exposed in source code",
        severity="critical"
    )
    
    output = generator.generate("sarif-report.json")
    print(f"Generated SARIF report with {len(generator.results)} findings")
    print(f"Rules defined: {len(generator.rules)}")
    print(json.dumps(output, indent=2)[:500] + "...")


if __name__ == "__main__":
    main()
