from pathlib import Path
import re
import sys


def markdown_files(root: Path) -> list[Path]:
    return [root / "README.md", *(root / "docs").rglob("*.md")]


def validate_file(root: Path, path: Path) -> list[str]:
    content = path.read_text()
    errors: list[str] = []
    if content.count("```") % 2:
        errors.append(f"{path}: unbalanced code fences")

    for target in re.findall(r"\[[^]]*\]\(([^)]+)\)", content):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        linked_path = (path.parent / target.split("#", 1)[0]).resolve()
        if not linked_path.exists():
            errors.append(f"{path}: broken link {target}")

    try:
        path.resolve().relative_to(root)
    except ValueError:
        errors.append(f"{path}: file is outside repository")
    return errors


def validate_use_case_coverage(root: Path) -> list[str]:
    specification = root / "docs/specifications/auth_module_specification_v2.1.md"
    required = set(re.findall(r"UC-\d{3}", specification.read_text()))
    errors: list[str] = []
    for relative_path in (
        "docs/specifications/requirements_traceability.md",
        "docs/specifications/auth-core_api_spec.md",
    ):
        path = root / relative_path
        documented = set(re.findall(r"UC-\d{3}", path.read_text()))
        missing = sorted(required - documented)
        if missing:
            errors.append(f"{path}: missing use cases {missing}")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    files = markdown_files(root)
    errors = [error for path in files for error in validate_file(root, path)]
    errors.extend(validate_use_case_coverage(root))
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Validated {len(files)} Markdown files and complete use-case coverage.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
