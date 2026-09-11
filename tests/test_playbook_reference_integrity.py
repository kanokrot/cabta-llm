"""Static integrity checks for playbook step references."""

import re
from pathlib import Path

import yaml


PLAYBOOK_DIR = Path(__file__).resolve().parents[1] / "data" / "playbooks"


def _walk_strings(value, path=()):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield from _walk_strings(nested, path + (str(key),))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _walk_strings(nested, path + (f"[{index}]",))
    elif isinstance(value, str):
        yield path, value


def test_for_each_results_are_not_referenced_by_bare_step_name():
    violations = []

    for playbook_path in sorted(PLAYBOOK_DIR.glob("*.yaml")):
        playbook = yaml.safe_load(playbook_path.read_text(encoding="utf-8")) or {}
        steps = playbook.get("steps", [])

        for producer_index, producer in enumerate(steps):
            producer_name = producer.get("name")
            if not producer_name or not producer.get("for_each"):
                continue

            bare_reference = re.compile(
                rf"\{{\{{\s*{re.escape(producer_name)}\s*\}}\}}"
            )
            for consumer in steps[producer_index + 1:]:
                for path, value in _walk_strings(consumer.get("params") or {}):
                    if bare_reference.search(value):
                        violations.append(
                            f"{playbook_path.name}: step '{consumer.get('name')}', "
                            f"param '{'.'.join(path)}' references bare "
                            f"{{{{{producer_name}}}}}; use _results/_items suffix"
                        )

    assert not violations, "Bare for_each references found:\n" + "\n".join(violations)
