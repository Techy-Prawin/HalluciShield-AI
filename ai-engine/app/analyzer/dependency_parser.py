import json
import re
import xml.etree.ElementTree as ET
from typing import List, Tuple
from app.analyzer.models import PackageReference, SecurityConstruct, FileInfo


class DependencyParser:
    CONFIG_FILENAMES = {
        ".env", ".env.example", ".env.local", "docker-compose.yml",
        "docker-compose.yaml", "dockerfile", "tsconfig.json",
        "settings.py", "config.json", "application.properties", "application.yml"
    }

    MANIFEST_FILENAMES = {
        "package.json", "requirements.txt", "pipfile", "pyproject.toml",
        "pom.xml", "build.gradle"
    }

    @classmethod
    def is_dependency_or_config(cls, filename: str) -> Tuple[bool, bool]:
        fn = filename.lower()
        is_dep = fn in cls.MANIFEST_FILENAMES
        is_cfg = fn in cls.CONFIG_FILENAMES or fn.startswith(".env")
        return is_dep, is_cfg

    @classmethod
    def parse_manifest(cls, file_path: str, relative_path: str, content: str) -> List[PackageReference]:
        packages: List[PackageReference] = []
        filename = relative_path.split("/")[-1].lower()

        if filename == "package.json":
            try:
                data = json.loads(content)
                deps = data.get("dependencies", {})
                for pkg, ver in deps.items():
                    packages.append(
                        PackageReference(
                            file_path=relative_path,
                            package_name=pkg,
                            version_spec=str(ver),
                            ecosystem="npm",
                            is_dev_dependency=False,
                        )
                    )
                dev_deps = data.get("devDependencies", {})
                for pkg, ver in dev_deps.items():
                    packages.append(
                        PackageReference(
                            file_path=relative_path,
                            package_name=pkg,
                            version_spec=str(ver),
                            ecosystem="npm",
                            is_dev_dependency=True,
                        )
                    )
            except Exception:
                pass

        elif filename == "requirements.txt":
            for line in content.splitlines():
                sline = line.strip()
                if not sline or sline.startswith("#") or sline.startswith("-"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:([=><~^]+.*))?$", sline)
                if match:
                    pkg = match.group(1)
                    ver = match.group(2) or "latest"
                    packages.append(
                        PackageReference(
                            file_path=relative_path,
                            package_name=pkg,
                            version_spec=ver,
                            ecosystem="PyPI",
                        )
                    )

        elif filename == "pom.xml":
            try:
                root = ET.fromstring(content)
                # Ignore XML namespaces
                for elem in root.iter():
                    if elem.tag.endswith("dependency"):
                        group_id = ""
                        artifact_id = ""
                        version = ""
                        for child in elem:
                            tag = child.tag.split("}")[-1]
                            if tag == "groupId":
                                group_id = child.text or ""
                            elif tag == "artifactId":
                                artifact_id = child.text or ""
                            elif tag == "version":
                                version = child.text or ""

                        if artifact_id:
                            pkg_name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                            packages.append(
                                PackageReference(
                                    file_path=relative_path,
                                    package_name=pkg_name,
                                    version_spec=version or "latest",
                                    ecosystem="Maven",
                                )
                            )
            except Exception:
                pass

        return packages

    @classmethod
    def parse_env_file(cls, relative_path: str, content: str) -> List[SecurityConstruct]:
        constructs: List[SecurityConstruct] = []
        for idx, line in enumerate(content.splitlines(), 1):
            sline = line.strip()
            if not sline or sline.startswith("#"):
                continue

            if "=" in sline:
                key, val = sline.split("=", 1)
                key = key.strip()
                val = val.strip()
                category = "ENV_VAR"
                desc = f"Environment variable entry '{key}'"

                if any(kw in key.upper() for kw in ["SECRET", "PASSWORD", "KEY", "TOKEN", "CREDENTIAL"]):
                    category = "SECRET_HARDCODED"
                    desc = f"Potential sensitive secret entry '{key}' in environment file"

                constructs.append(
                    SecurityConstruct(
                        file_path=relative_path,
                        line_number=idx,
                        category=category,
                        description=desc,
                        code_snippet=f"{key}={'***' if category == 'SECRET_HARDCODED' else val}",
                    )
                )

        return constructs
