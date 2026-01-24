#!/usr/bin/env python3
"""
Shellockolm SBOM Generator
Software Bill of Materials generator supporting CycloneDX and SPDX formats

Features:
- Generates SBOM from package.json and lockfiles
- Supports CycloneDX 1.4 (JSON)
- Supports SPDX 2.3 (JSON)
- Includes vulnerability annotations
- Supports npm, yarn, and pnpm lockfiles
"""

import json
import hashlib
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum


class SBOMFormat(Enum):
    """Supported SBOM formats"""
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class LicenseType(Enum):
    """Common npm license types"""
    MIT = "MIT"
    ISC = "ISC"
    APACHE_2 = "Apache-2.0"
    BSD_2 = "BSD-2-Clause"
    BSD_3 = "BSD-3-Clause"
    GPL_2 = "GPL-2.0"
    GPL_3 = "GPL-3.0"
    LGPL_2_1 = "LGPL-2.1"
    LGPL_3 = "LGPL-3.0"
    MPL_2 = "MPL-2.0"
    UNLICENSED = "UNLICENSED"
    UNKNOWN = "UNKNOWN"


@dataclass
class Component:
    """A software component (dependency)"""
    name: str
    version: str
    type: str = "library"  # application, framework, library, etc.
    purl: str = ""  # Package URL
    license: str = ""
    description: str = ""
    author: str = ""
    homepage: str = ""
    repository: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    is_dev: bool = False
    is_direct: bool = True

    def __post_init__(self):
        if not self.purl:
            self.purl = f"pkg:npm/{self.name}@{self.version}"


@dataclass
class SBOMMetadata:
    """SBOM metadata"""
    project_name: str
    project_version: str
    project_description: str = ""
    project_author: str = ""
    project_license: str = ""
    generator_name: str = "shellockolm"
    generator_version: str = "2.0.0"
    created: str = ""

    def __post_init__(self):
        if not self.created:
            self.created = datetime.now(timezone.utc).isoformat()


@dataclass
class SBOM:
    """Software Bill of Materials"""
    metadata: SBOMMetadata
    components: List[Component]
    format: SBOMFormat
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def total_components(self) -> int:
        return len(self.components)

    @property
    def direct_dependencies(self) -> List[Component]:
        return [c for c in self.components if c.is_direct]

    @property
    def transitive_dependencies(self) -> List[Component]:
        return [c for c in self.components if not c.is_direct]


class SBOMGenerator:
    """
    Generate Software Bill of Materials from npm projects
    """

    # CycloneDX spec version
    CYCLONEDX_VERSION = "1.4"
    CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.4.schema.json"

    # SPDX spec version
    SPDX_VERSION = "SPDX-2.3"

    def __init__(self):
        self.vuln_db = None  # Optional vulnerability database

    def _parse_package_json(self, pkg_json_path: Path) -> tuple:
        """Parse package.json and extract metadata and dependencies"""
        with open(pkg_json_path) as f:
            pkg_data = json.load(f)

        metadata = SBOMMetadata(
            project_name=pkg_data.get("name", "unknown"),
            project_version=pkg_data.get("version", "0.0.0"),
            project_description=pkg_data.get("description", ""),
            project_author=pkg_data.get("author", "") if isinstance(pkg_data.get("author"), str) else "",
            project_license=pkg_data.get("license", ""),
        )

        deps = pkg_data.get("dependencies", {})
        dev_deps = pkg_data.get("devDependencies", {})

        return metadata, deps, dev_deps

    def _parse_npm_lockfile(self, lockfile_path: Path) -> Dict[str, Dict]:
        """Parse package-lock.json"""
        with open(lockfile_path) as f:
            lock_data = json.load(f)

        packages = {}

        # npm v7+ format (packages)
        if "packages" in lock_data:
            for pkg_path, pkg_info in lock_data["packages"].items():
                if pkg_path == "":
                    continue  # Skip root

                # Extract package name from path
                parts = pkg_path.split("node_modules/")
                name = parts[-1] if parts else pkg_path

                version = pkg_info.get("version", "")
                if name and version:
                    packages[f"{name}@{version}"] = {
                        "name": name,
                        "version": version,
                        "resolved": pkg_info.get("resolved", ""),
                        "integrity": pkg_info.get("integrity", ""),
                        "dev": pkg_info.get("dev", False),
                        "license": pkg_info.get("license", ""),
                        "dependencies": list(pkg_info.get("dependencies", {}).keys()),
                    }
        # npm v6 format (dependencies)
        elif "dependencies" in lock_data:
            self._parse_npm_v6_deps(lock_data["dependencies"], packages)

        return packages

    def _parse_npm_v6_deps(self, deps: Dict, packages: Dict, parent: str = ""):
        """Recursively parse npm v6 lockfile dependencies"""
        for name, info in deps.items():
            version = info.get("version", "")
            key = f"{name}@{version}"

            if key not in packages:
                packages[key] = {
                    "name": name,
                    "version": version,
                    "resolved": info.get("resolved", ""),
                    "integrity": info.get("integrity", ""),
                    "dev": info.get("dev", False),
                    "license": "",
                    "dependencies": list(info.get("requires", {}).keys()) if info.get("requires") else [],
                }

            # Recursively process nested dependencies
            if "dependencies" in info:
                self._parse_npm_v6_deps(info["dependencies"], packages, name)

    def _parse_yarn_lockfile(self, lockfile_path: Path) -> Dict[str, Dict]:
        """Parse yarn.lock (v1 format)"""
        packages = {}

        with open(lockfile_path) as f:
            content = f.read()

        # Simple yarn.lock parser
        current_pkg = None
        current_data = {}

        for line in content.split("\n"):
            line = line.rstrip()

            if not line or line.startswith("#"):
                continue

            # Package header (e.g., "lodash@^4.17.0:")
            if not line.startswith(" ") and line.endswith(":"):
                if current_pkg and current_data.get("version"):
                    name = current_pkg.split("@")[0].strip('"')
                    version = current_data.get("version", "")
                    key = f"{name}@{version}"
                    packages[key] = {
                        "name": name,
                        "version": version,
                        "resolved": current_data.get("resolved", ""),
                        "integrity": current_data.get("integrity", ""),
                        "dev": False,
                        "license": "",
                        "dependencies": current_data.get("dependencies", []),
                    }

                current_pkg = line[:-1].split(",")[0].strip('"')
                current_data = {"dependencies": []}
            elif line.startswith("  version"):
                current_data["version"] = line.split('"')[1]
            elif line.startswith("  resolved"):
                current_data["resolved"] = line.split('"')[1]
            elif line.startswith("  integrity"):
                current_data["integrity"] = line.split()[1]
            elif line.startswith("    ") and "@" not in line and '"' in line:
                # Dependency name
                dep_name = line.strip().strip('"').split()[0].strip('"')
                current_data["dependencies"].append(dep_name)

        # Don't forget the last package
        if current_pkg and current_data.get("version"):
            name = current_pkg.split("@")[0].strip('"')
            version = current_data.get("version", "")
            key = f"{name}@{version}"
            packages[key] = {
                "name": name,
                "version": version,
                "resolved": current_data.get("resolved", ""),
                "integrity": current_data.get("integrity", ""),
                "dev": False,
                "license": "",
                "dependencies": current_data.get("dependencies", []),
            }

        return packages

    def _build_components(self, packages: Dict[str, Dict], direct_deps: Set[str],
                          dev_deps: Set[str]) -> List[Component]:
        """Build component list from parsed packages"""
        components = []

        for key, pkg_info in packages.items():
            name = pkg_info["name"]
            version = pkg_info["version"]

            # Parse integrity hash
            hashes = {}
            integrity = pkg_info.get("integrity", "")
            if integrity:
                if integrity.startswith("sha512-"):
                    hashes["SHA-512"] = integrity[7:]
                elif integrity.startswith("sha256-"):
                    hashes["SHA-256"] = integrity[7:]
                elif integrity.startswith("sha1-"):
                    hashes["SHA-1"] = integrity[5:]

            is_direct = name in direct_deps or name in dev_deps
            is_dev = pkg_info.get("dev", False) or name in dev_deps

            component = Component(
                name=name,
                version=version,
                type="library",
                license=pkg_info.get("license", ""),
                hashes=hashes,
                dependencies=pkg_info.get("dependencies", []),
                is_dev=is_dev,
                is_direct=is_direct,
            )

            components.append(component)

        # Sort: direct deps first, then alphabetically
        components.sort(key=lambda c: (not c.is_direct, c.name))

        return components

    def generate(self, project_path: str, format: SBOMFormat = SBOMFormat.CYCLONEDX,
                 include_dev: bool = True) -> SBOM:
        """
        Generate SBOM from npm project

        Args:
            project_path: Path to npm project
            format: Output format (CycloneDX or SPDX)
            include_dev: Include devDependencies

        Returns:
            SBOM object
        """
        project = Path(project_path).resolve()

        # Parse package.json
        pkg_json_path = project / "package.json"
        if not pkg_json_path.exists():
            raise FileNotFoundError(f"package.json not found at {project}")

        metadata, deps, dev_deps = self._parse_package_json(pkg_json_path)

        # Build direct dependency sets
        direct_deps = set(deps.keys())
        dev_dep_set = set(dev_deps.keys()) if include_dev else set()

        # Parse lockfile
        packages = {}
        lockfile_path = None

        if (project / "package-lock.json").exists():
            lockfile_path = project / "package-lock.json"
            packages = self._parse_npm_lockfile(lockfile_path)
        elif (project / "yarn.lock").exists():
            lockfile_path = project / "yarn.lock"
            packages = self._parse_yarn_lockfile(lockfile_path)
        else:
            # No lockfile - use package.json deps directly
            for name, version in deps.items():
                version = version.lstrip("^~>=<")
                packages[f"{name}@{version}"] = {
                    "name": name,
                    "version": version,
                    "resolved": "",
                    "integrity": "",
                    "dev": False,
                    "license": "",
                    "dependencies": [],
                }
            if include_dev:
                for name, version in dev_deps.items():
                    version = version.lstrip("^~>=<")
                    packages[f"{name}@{version}"] = {
                        "name": name,
                        "version": version,
                        "resolved": "",
                        "integrity": "",
                        "dev": True,
                        "license": "",
                        "dependencies": [],
                    }

        # Build components
        components = self._build_components(packages, direct_deps, dev_dep_set)

        return SBOM(
            metadata=metadata,
            components=components,
            format=format
        )

    def to_cyclonedx(self, sbom: SBOM) -> Dict[str, Any]:
        """Convert SBOM to CycloneDX JSON format"""
        # Generate unique serial number
        serial = f"urn:uuid:{uuid.uuid4()}"

        # Build component list
        components = []
        for comp in sbom.components:
            component = {
                "type": comp.type,
                "bom-ref": f"{comp.name}@{comp.version}",
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
            }

            if comp.license:
                component["licenses"] = [{"license": {"id": comp.license}}]

            if comp.description:
                component["description"] = comp.description

            if comp.hashes:
                component["hashes"] = [
                    {"alg": alg, "content": hash_val}
                    for alg, hash_val in comp.hashes.items()
                ]

            if comp.is_dev:
                component["scope"] = "optional"

            components.append(component)

        # Build dependencies
        dependencies = []
        for comp in sbom.components:
            dep_refs = []
            for dep in comp.dependencies:
                # Find the actual version in our components
                for c in sbom.components:
                    if c.name == dep:
                        dep_refs.append(f"{c.name}@{c.version}")
                        break
            dependencies.append({
                "ref": f"{comp.name}@{comp.version}",
                "dependsOn": dep_refs
            })

        # Build BOM
        bom = {
            "$schema": self.CYCLONEDX_SCHEMA,
            "bomFormat": "CycloneDX",
            "specVersion": self.CYCLONEDX_VERSION,
            "serialNumber": serial,
            "version": 1,
            "metadata": {
                "timestamp": sbom.metadata.created,
                "tools": [{
                    "vendor": "shellockolm",
                    "name": sbom.metadata.generator_name,
                    "version": sbom.metadata.generator_version
                }],
                "component": {
                    "type": "application",
                    "name": sbom.metadata.project_name,
                    "version": sbom.metadata.project_version,
                }
            },
            "components": components,
            "dependencies": dependencies
        }

        if sbom.metadata.project_description:
            bom["metadata"]["component"]["description"] = sbom.metadata.project_description

        if sbom.metadata.project_license:
            bom["metadata"]["component"]["licenses"] = [{"license": {"id": sbom.metadata.project_license}}]

        # Add vulnerabilities if present
        if sbom.vulnerabilities:
            bom["vulnerabilities"] = sbom.vulnerabilities

        return bom

    def to_spdx(self, sbom: SBOM) -> Dict[str, Any]:
        """Convert SBOM to SPDX 2.3 JSON format"""
        # Generate document namespace
        namespace = f"https://shellockolm.dev/sbom/{sbom.metadata.project_name}/{sbom.metadata.project_version}/{uuid.uuid4()}"

        # Build packages list
        packages = []

        # Add root package
        root_pkg = {
            "SPDXID": "SPDXRef-Package",
            "name": sbom.metadata.project_name,
            "versionInfo": sbom.metadata.project_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
        }

        if sbom.metadata.project_license:
            root_pkg["licenseConcluded"] = sbom.metadata.project_license
            root_pkg["licenseDeclared"] = sbom.metadata.project_license
        else:
            root_pkg["licenseConcluded"] = "NOASSERTION"
            root_pkg["licenseDeclared"] = "NOASSERTION"

        if sbom.metadata.project_description:
            root_pkg["description"] = sbom.metadata.project_description

        packages.append(root_pkg)

        # Add component packages
        for i, comp in enumerate(sbom.components):
            spdx_id = f"SPDXRef-Package-{i+1}"

            pkg = {
                "SPDXID": spdx_id,
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl
                }]
            }

            if comp.license:
                pkg["licenseConcluded"] = comp.license
                pkg["licenseDeclared"] = comp.license
            else:
                pkg["licenseConcluded"] = "NOASSERTION"
                pkg["licenseDeclared"] = "NOASSERTION"

            if comp.hashes:
                checksums = []
                for alg, hash_val in comp.hashes.items():
                    checksums.append({
                        "algorithm": alg.replace("-", ""),
                        "checksumValue": hash_val
                    })
                if checksums:
                    pkg["checksums"] = checksums

            packages.append(pkg)

        # Build relationships
        relationships = []

        # Root describes relationship
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package"
        })

        # Dependency relationships
        for i, comp in enumerate(sbom.components):
            if comp.is_direct:
                relationships.append({
                    "spdxElementId": "SPDXRef-Package",
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": f"SPDXRef-Package-{i+1}"
                })

        # Build SPDX document
        spdx = {
            "spdxVersion": self.SPDX_VERSION,
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{sbom.metadata.project_name}-{sbom.metadata.project_version}",
            "documentNamespace": namespace,
            "creationInfo": {
                "created": sbom.metadata.created,
                "creators": [
                    f"Tool: {sbom.metadata.generator_name}-{sbom.metadata.generator_version}"
                ]
            },
            "packages": packages,
            "relationships": relationships
        }

        return spdx

    def export(self, sbom: SBOM, output_path: str) -> str:
        """
        Export SBOM to file

        Args:
            sbom: SBOM object to export
            output_path: Output file path

        Returns:
            Path to exported file
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        if sbom.format == SBOMFormat.CYCLONEDX:
            data = self.to_cyclonedx(sbom)
        else:
            data = self.to_spdx(sbom)

        with open(output, "w") as f:
            json.dump(data, f, indent=2)

        return str(output)

    def generate_report(self, sbom: SBOM) -> Dict[str, Any]:
        """Generate a summary report from SBOM"""
        licenses = {}
        for comp in sbom.components:
            lic = comp.license or "UNKNOWN"
            licenses[lic] = licenses.get(lic, 0) + 1

        return {
            "project": {
                "name": sbom.metadata.project_name,
                "version": sbom.metadata.project_version,
                "license": sbom.metadata.project_license,
            },
            "components": {
                "total": sbom.total_components,
                "direct": len(sbom.direct_dependencies),
                "transitive": len(sbom.transitive_dependencies),
                "dev_dependencies": sum(1 for c in sbom.components if c.is_dev),
            },
            "licenses": licenses,
            "format": sbom.format.value,
            "generated": sbom.metadata.created,
        }


# ─────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for testing"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python sbom_generator.py <project-path> [--spdx]")
        sys.exit(1)

    project_path = sys.argv[1]
    use_spdx = "--spdx" in sys.argv

    format = SBOMFormat.SPDX if use_spdx else SBOMFormat.CYCLONEDX

    print(f"Generating SBOM for: {project_path}")
    print(f"Format: {format.value}")
    print("-" * 50)

    generator = SBOMGenerator()

    try:
        sbom = generator.generate(project_path, format=format)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)

    report = generator.generate_report(sbom)

    print(f"Project: {report['project']['name']}@{report['project']['version']}")
    print(f"Total Components: {report['components']['total']}")
    print(f"  Direct: {report['components']['direct']}")
    print(f"  Transitive: {report['components']['transitive']}")
    print(f"  Dev: {report['components']['dev_dependencies']}")
    print()

    print("License Distribution:")
    for lic, count in sorted(report['licenses'].items(), key=lambda x: -x[1])[:10]:
        print(f"  {lic}: {count}")
    print()

    # Export
    output_file = f"sbom.{format.value}.json"
    generator.export(sbom, output_file)
    print(f"SBOM exported to: {output_file}")


if __name__ == "__main__":
    main()
