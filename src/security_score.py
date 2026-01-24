#!/usr/bin/env python3
"""
Shellockolm Security Score Calculator
Calculates security grade (A-F) for npm projects based on multiple factors

Scoring factors:
- Vulnerability count and severity
- Outdated dependencies
- Malware presence
- Secrets exposure
- Security configurations
- Dependency health
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Import scanners
try:
    from vulnerability_database import VulnerabilityDatabase, Severity
    from malware_analyzer import MalwareAnalyzer, ThreatLevel
    from secrets_scanner import SecretsScanner, SecretSeverity
except ImportError:
    pass


class SecurityGrade(Enum):
    """Security grade levels"""
    A_PLUS = "A+"   # 95-100: Excellent security
    A = "A"         # 90-94: Very good
    B = "B"         # 80-89: Good
    C = "C"         # 70-79: Needs improvement
    D = "D"         # 60-69: Poor
    F = "F"         # Below 60: Critical issues


@dataclass
class ScoreBreakdown:
    """Breakdown of security score components"""
    vulnerabilities: int = 100      # Max 30 points
    malware: int = 100              # Max 25 points
    secrets: int = 100              # Max 20 points
    dependencies: int = 100         # Max 15 points
    configuration: int = 100        # Max 10 points

    @property
    def total(self) -> int:
        """Calculate weighted total score"""
        weights = {
            'vulnerabilities': 0.30,
            'malware': 0.25,
            'secrets': 0.20,
            'dependencies': 0.15,
            'configuration': 0.10,
        }
        return int(
            self.vulnerabilities * weights['vulnerabilities'] +
            self.malware * weights['malware'] +
            self.secrets * weights['secrets'] +
            self.dependencies * weights['dependencies'] +
            self.configuration * weights['configuration']
        )


@dataclass
class SecurityIssue:
    """A security issue found during scoring"""
    category: str
    severity: str
    title: str
    description: str
    impact: int  # Points deducted
    remediation: str


@dataclass
class SecurityReport:
    """Complete security assessment report"""
    project_path: str
    scan_time: datetime
    grade: SecurityGrade
    score: int
    breakdown: ScoreBreakdown
    issues: List[SecurityIssue] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)


class SecurityScoreCalculator:
    """
    Calculates comprehensive security score for npm projects
    """

    # Severity impact scores
    VULN_SEVERITY_IMPACT = {
        'CRITICAL': 15,  # Each critical vuln deducts 15 points
        'HIGH': 10,
        'MEDIUM': 5,
        'LOW': 2,
    }

    MALWARE_SEVERITY_IMPACT = {
        'CRITICAL': 25,  # Malware is serious
        'HIGH': 15,
        'MEDIUM': 8,
        'LOW': 3,
    }

    SECRET_SEVERITY_IMPACT = {
        'CRITICAL': 20,
        'HIGH': 12,
        'MEDIUM': 5,
        'LOW': 2,
    }

    def __init__(self):
        self.vuln_db = VulnerabilityDatabase()

    def score_to_grade(self, score: int) -> SecurityGrade:
        """Convert numeric score to letter grade"""
        if score >= 95:
            return SecurityGrade.A_PLUS
        elif score >= 90:
            return SecurityGrade.A
        elif score >= 80:
            return SecurityGrade.B
        elif score >= 70:
            return SecurityGrade.C
        elif score >= 60:
            return SecurityGrade.D
        else:
            return SecurityGrade.F

    def calculate_vulnerability_score(self, project_path: str) -> Tuple[int, List[SecurityIssue]]:
        """Calculate score based on CVE vulnerabilities"""
        from scanners import get_all_scanners

        score = 100
        issues = []

        # Run all vulnerability scanners
        scanners = get_all_scanners()
        total_findings = []

        for scanner in scanners:
            try:
                result = scanner.scan_directory(project_path, recursive=True, max_depth=5)
                total_findings.extend(result.findings)
            except Exception:
                pass

        # Deduct points based on severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for finding in total_findings:
            sev = finding.severity.value.upper() if hasattr(finding.severity, 'value') else str(finding.severity).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
                impact = self.VULN_SEVERITY_IMPACT.get(sev, 0)
                score = max(0, score - impact)

                issues.append(SecurityIssue(
                    category="Vulnerability",
                    severity=sev,
                    title=f"{finding.cve_id}: {finding.title}",
                    description=finding.description[:100] if finding.description else "",
                    impact=impact,
                    remediation=finding.remediation or "Upgrade to patched version",
                ))

        return max(0, score), issues

    def calculate_malware_score(self, project_path: str) -> Tuple[int, List[SecurityIssue]]:
        """Calculate score based on malware presence"""
        score = 100
        issues = []

        try:
            analyzer = MalwareAnalyzer()
            report = analyzer.scan_directory(project_path, scan_node_modules=False, max_depth=5)

            for match in report.matches:
                sev = match.threat_level.value.upper()
                impact = self.MALWARE_SEVERITY_IMPACT.get(sev, 0)
                score = max(0, score - impact)

                issues.append(SecurityIssue(
                    category="Malware",
                    severity=sev,
                    title=match.pattern_name,
                    description=match.explanation[:100] if match.explanation else "",
                    impact=impact,
                    remediation=match.remediation or "Remove malicious code",
                ))

        except Exception:
            pass

        return max(0, score), issues

    def calculate_secrets_score(self, project_path: str) -> Tuple[int, List[SecurityIssue]]:
        """Calculate score based on exposed secrets"""
        score = 100
        issues = []

        try:
            scanner = SecretsScanner()
            report = scanner.scan_directory(project_path, max_depth=5)

            for match in report.matches:
                sev = match.pattern.severity.value.upper()
                impact = self.SECRET_SEVERITY_IMPACT.get(sev, 0)
                score = max(0, score - impact)

                issues.append(SecurityIssue(
                    category="Secret",
                    severity=sev,
                    title=match.pattern.name,
                    description=f"Found in {match.file_path}:{match.line_number}",
                    impact=impact,
                    remediation=match.pattern.remediation or "Remove hardcoded secret",
                ))

        except Exception:
            pass

        return max(0, score), issues

    def calculate_dependency_score(self, project_path: str) -> Tuple[int, List[SecurityIssue]]:
        """Calculate score based on dependency health"""
        score = 100
        issues = []

        pkg_json_path = Path(project_path) / "package.json"
        if not pkg_json_path.exists():
            return score, issues

        try:
            pkg_data = json.loads(pkg_json_path.read_text())
        except Exception:
            return score, issues

        deps = pkg_data.get("dependencies", {})
        dev_deps = pkg_data.get("devDependencies", {})
        all_deps = {**deps, **dev_deps}

        # Check for known problematic patterns
        problematic = {
            # Deprecated packages
            'request': ('deprecated', 10, 'Use axios or node-fetch instead'),
            'node-uuid': ('deprecated', 5, 'Use uuid package instead'),
            'mkdirp': ('deprecated', 3, 'Use fs.mkdir with recursive option'),

            # Known vulnerable without specific CVE tracking
            'event-stream': ('malware-history', 15, 'Package was compromised in 2018'),
            'flatmap-stream': ('malware', 20, 'Known malicious package'),
            'eslint-scope': ('compromised-history', 10, 'Package was compromised'),
        }

        for dep_name in all_deps:
            if dep_name in problematic:
                issue_type, impact, remediation = problematic[dep_name]
                score = max(0, score - impact)
                issues.append(SecurityIssue(
                    category="Dependency",
                    severity="HIGH" if impact >= 10 else "MEDIUM",
                    title=f"Problematic dependency: {dep_name}",
                    description=f"This package is {issue_type}",
                    impact=impact,
                    remediation=remediation,
                ))

        # Check for wildcard versions (very dangerous)
        for dep_name, version in all_deps.items():
            if version in ('*', 'latest', ''):
                score = max(0, score - 8)
                issues.append(SecurityIssue(
                    category="Dependency",
                    severity="HIGH",
                    title=f"Wildcard version: {dep_name}",
                    description=f"Using '{version}' allows any version including malicious ones",
                    impact=8,
                    remediation="Pin to specific version",
                ))

        # Check for git dependencies (can change without warning)
        for dep_name, version in all_deps.items():
            if isinstance(version, str) and ('git' in version or 'github' in version):
                score = max(0, score - 5)
                issues.append(SecurityIssue(
                    category="Dependency",
                    severity="MEDIUM",
                    title=f"Git dependency: {dep_name}",
                    description="Git dependencies can change without version control",
                    impact=5,
                    remediation="Pin to specific commit or use npm package",
                ))

        return max(0, score), issues

    def calculate_configuration_score(self, project_path: str) -> Tuple[int, List[SecurityIssue]]:
        """Calculate score based on security configurations"""
        score = 100
        issues = []
        project = Path(project_path)

        # Check for .npmrc with ignore-scripts
        npmrc_path = project / ".npmrc"
        has_ignore_scripts = False
        if npmrc_path.exists():
            try:
                content = npmrc_path.read_text()
                has_ignore_scripts = 'ignore-scripts=true' in content
            except Exception:
                pass

        if not has_ignore_scripts:
            score = max(0, score - 5)
            issues.append(SecurityIssue(
                category="Configuration",
                severity="LOW",
                title="Scripts not disabled in .npmrc",
                description="Malicious packages can run code during npm install",
                impact=5,
                remediation="Add 'ignore-scripts=true' to .npmrc for sensitive environments",
            ))

        # Check for package-lock.json
        if not (project / "package-lock.json").exists() and not (project / "yarn.lock").exists():
            score = max(0, score - 10)
            issues.append(SecurityIssue(
                category="Configuration",
                severity="HIGH",
                title="No lockfile found",
                description="Without lockfile, builds are not reproducible and vulnerable to supply chain attacks",
                impact=10,
                remediation="Run 'npm install' to generate package-lock.json",
            ))

        # Check for .gitignore with sensitive patterns
        gitignore_path = project / ".gitignore"
        if gitignore_path.exists():
            try:
                content = gitignore_path.read_text().lower()
                if '.env' not in content:
                    score = max(0, score - 5)
                    issues.append(SecurityIssue(
                        category="Configuration",
                        severity="MEDIUM",
                        title=".env not in .gitignore",
                        description="Environment files may be committed with secrets",
                        impact=5,
                        remediation="Add '.env*' to .gitignore",
                    ))
            except Exception:
                pass
        else:
            score = max(0, score - 3)
            issues.append(SecurityIssue(
                category="Configuration",
                severity="LOW",
                title="No .gitignore file",
                description="Sensitive files may be committed accidentally",
                impact=3,
                remediation="Create a .gitignore file",
            ))

        # Check for npm audit configuration
        pkg_json_path = project / "package.json"
        if pkg_json_path.exists():
            try:
                pkg_data = json.loads(pkg_json_path.read_text())
                scripts = pkg_data.get("scripts", {})

                # Good practice: audit in CI
                has_audit = any('audit' in v for v in scripts.values())
                if not has_audit:
                    score = max(0, score - 3)
                    issues.append(SecurityIssue(
                        category="Configuration",
                        severity="LOW",
                        title="No security audit script",
                        description="Consider adding 'npm audit' to your CI/CD pipeline",
                        impact=3,
                        remediation="Add 'audit': 'npm audit' to scripts",
                    ))
            except Exception:
                pass

        return max(0, score), issues

    def calculate_score(self, project_path: str) -> SecurityReport:
        """Calculate complete security score for a project"""
        all_issues = []

        # Calculate each component
        vuln_score, vuln_issues = self.calculate_vulnerability_score(project_path)
        all_issues.extend(vuln_issues)

        malware_score, malware_issues = self.calculate_malware_score(project_path)
        all_issues.extend(malware_issues)

        secrets_score, secrets_issues = self.calculate_secrets_score(project_path)
        all_issues.extend(secrets_issues)

        deps_score, deps_issues = self.calculate_dependency_score(project_path)
        all_issues.extend(deps_issues)

        config_score, config_issues = self.calculate_configuration_score(project_path)
        all_issues.extend(config_issues)

        # Create breakdown
        breakdown = ScoreBreakdown(
            vulnerabilities=vuln_score,
            malware=malware_score,
            secrets=secrets_score,
            dependencies=deps_score,
            configuration=config_score,
        )

        # Calculate total and grade
        total_score = breakdown.total
        grade = self.score_to_grade(total_score)

        # Generate recommendations based on lowest scores
        recommendations = []
        if vuln_score < 80:
            recommendations.append("Run 'npm audit fix' to patch vulnerable packages")
        if malware_score < 80:
            recommendations.append("Scan and remove malicious code with shellockolm malware-scan")
        if secrets_score < 80:
            recommendations.append("Remove hardcoded secrets and use environment variables")
        if deps_score < 80:
            recommendations.append("Review and update problematic dependencies")
        if config_score < 80:
            recommendations.append("Improve security configuration (lockfile, .gitignore, etc.)")

        # Add general recommendation
        if total_score < 70:
            recommendations.append("Consider a security audit by a professional")

        return SecurityReport(
            project_path=project_path,
            scan_time=datetime.now(),
            grade=grade,
            score=total_score,
            breakdown=breakdown,
            issues=all_issues,
            recommendations=recommendations,
            stats={
                "total_issues": len(all_issues),
                "critical_issues": sum(1 for i in all_issues if i.severity == "CRITICAL"),
                "high_issues": sum(1 for i in all_issues if i.severity == "HIGH"),
                "medium_issues": sum(1 for i in all_issues if i.severity == "MEDIUM"),
                "low_issues": sum(1 for i in all_issues if i.severity == "LOW"),
            },
        )

    def generate_report(self, report: SecurityReport, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate detailed security report"""
        output = {
            "project_path": report.project_path,
            "scan_time": report.scan_time.isoformat(),
            "grade": report.grade.value,
            "score": report.score,
            "breakdown": {
                "vulnerabilities": report.breakdown.vulnerabilities,
                "malware": report.breakdown.malware,
                "secrets": report.breakdown.secrets,
                "dependencies": report.breakdown.dependencies,
                "configuration": report.breakdown.configuration,
            },
            "stats": report.stats,
            "issues": [
                {
                    "category": i.category,
                    "severity": i.severity,
                    "title": i.title,
                    "description": i.description,
                    "impact": i.impact,
                    "remediation": i.remediation,
                }
                for i in report.issues
            ],
            "recommendations": report.recommendations,
        }

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(json.dumps(output, indent=2))

        return output

    def print_report(self, report: SecurityReport):
        """Print a formatted security report to console"""
        grade_colors = {
            SecurityGrade.A_PLUS: "\033[92m",  # Green
            SecurityGrade.A: "\033[92m",
            SecurityGrade.B: "\033[93m",       # Yellow
            SecurityGrade.C: "\033[93m",
            SecurityGrade.D: "\033[91m",       # Red
            SecurityGrade.F: "\033[91m",
        }
        reset = "\033[0m"
        color = grade_colors.get(report.grade, "")

        print(f"\n{'=' * 60}")
        print(f"  SECURITY SCORE: {color}{report.grade.value}{reset} ({report.score}/100)")
        print(f"{'=' * 60}")
        print(f"\n  Breakdown:")
        print(f"    Vulnerabilities:  {report.breakdown.vulnerabilities:3}/100 (30% weight)")
        print(f"    Malware:          {report.breakdown.malware:3}/100 (25% weight)")
        print(f"    Secrets:          {report.breakdown.secrets:3}/100 (20% weight)")
        print(f"    Dependencies:     {report.breakdown.dependencies:3}/100 (15% weight)")
        print(f"    Configuration:    {report.breakdown.configuration:3}/100 (10% weight)")

        print(f"\n  Issues Found: {report.stats['total_issues']}")
        print(f"    Critical: {report.stats['critical_issues']}")
        print(f"    High:     {report.stats['high_issues']}")
        print(f"    Medium:   {report.stats['medium_issues']}")
        print(f"    Low:      {report.stats['low_issues']}")

        if report.recommendations:
            print(f"\n  Recommendations:")
            for rec in report.recommendations:
                print(f"    • {rec}")

        print(f"\n{'=' * 60}\n")


def main():
    """CLI entry point"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python security_score.py <project-path>")
        sys.exit(1)

    calculator = SecurityScoreCalculator()
    report = calculator.calculate_score(sys.argv[1])
    calculator.print_report(report)


if __name__ == "__main__":
    main()
