"""Testes do agendador cron (5 campos) e persistência das configurações."""
from datetime import datetime

import pytest
from mandacaru_win.schedule import (
    DEFAULT_CRON,
    CronError,
    ScheduleConfig,
    ScheduleStore,
    describe_cron,
    parse_cron,
)


def test_default_cron_every_four_hours():
    s = parse_cron(DEFAULT_CRON)
    assert s.expr == "0 */4 * * *"
    assert s.hours == frozenset({0, 4, 8, 12, 16, 20})
    assert s.minutes == frozenset({0})
    assert s.next_run(datetime(2026, 11, 23, 10, 15)) == datetime(2026, 11, 23, 12, 0)
    assert s.next_run(datetime(2026, 11, 23, 20, 0)) == datetime(2026, 11, 24, 0, 0)


def test_cron_ranges_lists_steps_and_weekday():
    # Segunda a sexta às 09:30 (2026-11-21 é sábado, 2026-11-23 é segunda)
    s = parse_cron("30 9 * * 1-5")
    assert s.next_run(datetime(2026, 11, 21, 10, 0)) == datetime(2026, 11, 23, 9, 30)

    # Domingo aceita 0 ou 7 (2026-11-22 é domingo)
    dom = parse_cron("0 8 * * 7")
    assert dom.matches(datetime(2026, 11, 22, 8, 0))
    assert not dom.matches(datetime(2026, 11, 23, 8, 0))

    # Lista e passo em minutos
    m = parse_cron("*/15 10,14 * * *")
    assert m.next_run(datetime(2026, 11, 23, 10, 16)) == datetime(2026, 11, 23, 10, 30)
    assert m.next_run(datetime(2026, 11, 23, 10, 45)) == datetime(2026, 11, 23, 14, 0)


@pytest.mark.parametrize("bad", [
    "",
    "0 */4 * *",
    "0 */4 * * * *",
    "60 * * * *",
    "0 24 * * *",
    "0 0 0 * *",
    "0 0 * 13 *",
    "0 */0 * * *",
    "10-5 * * * *",
    "abc * * * *",
])
def test_invalid_cron_raises(bad):
    with pytest.raises(CronError):
        parse_cron(bad)


def test_describe_cron():
    assert "4 horas" in describe_cron("0 */4 * * *")
    assert "15 minuto" in describe_cron("*/15 * * * *")
    assert "12:30" in describe_cron("30 12 * * *")


def test_schedule_store_defaults_save_mark_and_corrupt(tmp_path):
    p = tmp_path / "schedule.json"
    st = ScheduleStore(p)
    cfg = st.get()
    assert cfg.enabled is True and cfg.cron == DEFAULT_CRON and cfg.minimize_to_tray is True

    st.save(ScheduleConfig(enabled=False, cron="30 12 * * *", paths=[str(tmp_path)], minimize_to_tray=False))
    reloaded = ScheduleStore(p).get()
    assert not reloaded.enabled and reloaded.cron == "30 12 * * *"
    assert reloaded.paths == [str(tmp_path.resolve())] and not reloaded.minimize_to_tray

    st.mark_run(1234.5)
    assert ScheduleStore(p).get().last_run == 1234.5

    p.write_text("{quebrado")
    assert ScheduleStore(p).get().cron == DEFAULT_CRON
    assert (tmp_path / "schedule.json.corrompido").read_text() == "{quebrado"
