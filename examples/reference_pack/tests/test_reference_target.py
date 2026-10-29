"""`reference-requirements://` keeps the target contract, checked by Guardana's own kit."""

from pathlib import Path

import pytest
from guardana.core import Capability, LocatorError
from guardana.testing import TargetContractError, assert_target_conforms
from guardana_reference_pack import provide_targets
from guardana_reference_pack.target import ReferenceRequirementsTarget


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    """A directory with requirement files in two cases, a subdirectory and a Python file."""
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    (tmp_path / "REQUIREMENTS-dev.IN").write_text("pytest\n", encoding="utf-8")
    (tmp_path / "service").mkdir()
    (tmp_path / "service" / "requirements.txt").write_text("idna==3.7\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    return tmp_path


def test_the_target_keeps_the_target_contract(tree: Path) -> None:
    assert_target_conforms(ReferenceRequirementsTarget(tree))


def test_the_check_refuses_a_target_that_reads_files_and_does_not_say_so(tree: Path) -> None:
    class Undeclared(ReferenceRequirementsTarget):
        def capabilities(self) -> set[Capability]:
            return set()

    with pytest.raises(TargetContractError, match="does not declare read_files"):
        assert_target_conforms(Undeclared(tree))


def test_the_target_lists_requirement_files_only_in_a_stable_order(tree: Path) -> None:
    listed = [
        p.relative_to(tree).as_posix() for p in ReferenceRequirementsTarget(tree).iter_files()
    ]

    assert listed == ["REQUIREMENTS-dev.IN", "requirements.txt", "service/requirements.txt"]


def test_the_entry_point_registers_the_target_under_its_scheme() -> None:
    assert provide_targets() == [ReferenceRequirementsTarget]
    assert ReferenceRequirementsTarget.scheme == "reference-requirements"


def test_a_locator_is_refused_for_a_missing_directory_and_for_options(tmp_path: Path) -> None:
    with pytest.raises(LocatorError, match="is not a directory"):
        ReferenceRequirementsTarget.from_locator(str(tmp_path / "absent"), options={})
    with pytest.raises(LocatorError, match="accepts no target options"):
        ReferenceRequirementsTarget.from_locator(str(tmp_path), options={"depth": "1"})


def test_a_locator_names_the_directory_in_the_ref(tmp_path: Path) -> None:
    target = ReferenceRequirementsTarget.from_locator(str(tmp_path), options={})

    assert target.ref == f"reference-requirements://{tmp_path}"
