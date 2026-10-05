from pathlib import Path

from src.integrations.ticketing import _get_db_path


def test_default_ticketing_db_is_under_test_tmp_path(tmp_path):
    db_path = Path(_get_db_path()).resolve()
    data_path = (Path(__file__).resolve().parents[1] / "data").resolve()

    assert db_path != data_path / "tickets" / "tickets.db"
    assert data_path not in (db_path, *db_path.parents)
    assert tmp_path.resolve() in db_path.parents
