"""Offline forecasts preserve unknown prices and bound every planned call."""

import copy
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

import pytest

from services.probe_cost_forecast import PlanError, forecast
from scripts.probe_cost_forecast import main

CHECK = unittest.TestCase()
INPUT_CAP, OUTPUT_CAP = 100, 20


def paid_plan(**changes):
    probe = {
        "kind": "generation", "enabled": True, "provider": "openai",
        "models": ["m1", "m2"], "key_count": 3, "probes_per_interval": 2,
        "interval_minutes": 30, "input_token_cap": INPUT_CAP, "output_token_cap": OUTPUT_CAP,
    }
    probe.update(changes)
    return {"days": 30, "run_minutes": 60, "probes": [probe],
            "pricing": {"openai:*": {"input": "2", "output": "8"}}}


def scheduled_plan(**changes):
    schedule = {"enabled": True, "admin_configured": True, "container_running": True}
    schedule.update(changes)
    return {
        "schedule": schedule,
        "routes": [{"id": "auto:a", "candidates": ["nanogpt:a", "nanogpt:b", "openrouter:a"]},
                   {"id": "auto:b", "candidates": ["nanogpt:a"]}],
        "providers": {
            "nanogpt": {"catalog_check": True, "base_url_configured": True, "key_count": 8},
            "openrouter": {"catalog_check": True, "base_url_configured": True,
                           "public_catalog": True, "key_count": 0},
        },
    }


def test_multipliers_and_worst_case_tokens():
    report = forecast(paid_plan())
    CHECK.assertEqual(report['calls'], {'daily': 576, 'month': 17280, 'max_run': 24})
    CHECK.assertEqual(report['generation_calls'], report['calls'])
    CHECK.assertEqual(report['cost_usd'], {'daily': '0.207360', 'month': '6.220800', 'max_run': '0.008640'})
    CHECK.assertTrue(not report['incomplete'])
    CHECK.assertEqual(len(report['priced_components']), 2)
    CHECK.assertEqual(report['components'][0]['input_token_cap'], 100)
    CHECK.assertEqual(report['components'][0]['probes_per_interval'], 2)


def test_scheduled_checks_deduplicate_models_routes_and_keys():
    report = forecast(scheduled_plan())
    CHECK.assertEqual(report['calls']['daily'], 96)
    CHECK.assertEqual(report['generation_calls']['daily'], 0)
    CHECK.assertTrue(report['zero_generation'] is True)
    CHECK.assertTrue(report['cost_usd']['daily'] is None)
    CHECK.assertTrue(report['incomplete'] is True)
    CHECK.assertEqual(len(report['unknown_components']), 2)
    CHECK.assertEqual(report['components'][0]['models'], ['a', 'b'])
    CHECK.assertEqual(report['components'][0]['key_count'], 8)


@pytest.mark.parametrize("changes", [{"enabled": False}, {"admin_configured": False},
                                     {"container_running": False}])
def test_scheduled_checks_require_running_container_or_explicit_wake(changes):
    CHECK.assertEqual(forecast(scheduled_plan(**changes))['calls']['daily'], 0)


@pytest.mark.parametrize("flag", ["checks_wake", "keep_warm"])
def test_wake_and_keep_warm_make_asleep_checks_eligible(flag):
    report = forecast(scheduled_plan(container_running=False, **{flag: True}))
    model_lists = [row for row in report["components"] if row["kind"] == "model_list"]
    CHECK.assertEqual(sum((row['calls']['daily'] for row in model_lists)), 96)
    if flag == "keep_warm":
        CHECK.assertEqual(report['calls']['daily'], 384)


def test_five_minute_cron_intersection_and_window_ceiling():
    plan = scheduled_plan(interval_minutes=7)
    plan["run_minutes"] = 36
    report = forecast(plan)
    CHECK.assertEqual(report['schedule']['effective_interval_minutes'], 35)
    CHECK.assertEqual(report['calls']['daily'], 84)
    CHECK.assertEqual(report['calls']['max_run'], 4)


def test_skipped_catalog_and_missing_keys_are_not_calls():
    plan = scheduled_plan()
    plan["providers"]["nanogpt"]["key_count"] = 0
    plan["providers"]["openrouter"]["catalog_check"] = False
    CHECK.assertEqual(forecast(plan)['calls']['daily'], 0)


def test_explicit_model_list_price_does_not_use_token_price():
    plan = scheduled_plan()
    plan["pricing"] = {"*": {"input": 0, "output": 0}}
    report = forecast(plan)
    CHECK.assertTrue(report['cost_usd']['daily'] is None)
    for provider in plan["providers"].values():
        provider["model_list_request_usd"] = "0.000000001"
    report = forecast(plan)
    CHECK.assertEqual(report['cost_usd']['daily'], '0.000001')
    CHECK.assertEqual(report['cost_micro_usd']['daily'], 1)


def test_unknown_price_is_not_zero_and_partial_known_cost_is_retained():
    plan = paid_plan()
    plan["pricing"] = {"openai:m1": {"input": 2, "output": 8}}
    report = forecast(plan)
    CHECK.assertTrue(report['cost_usd']['daily'] is None)
    CHECK.assertEqual(report['known_cost_usd']['daily'], '0.103680')
    CHECK.assertEqual(len(report['unknown_components']), 1)


def test_prices_use_exact_provider_and_global_precedence_and_aliases():
    plan = paid_plan()
    plan["pricing"] = {"OPENAI:M1": {"input_cost_per_million": 1, "output_cost_per_million": 2},
                       "openai:*": {"input": 2, "output": 4}, "*": {"input": 10, "output": 20}}
    report = forecast(plan)
    CHECK.assertEqual(report['cost_usd']['daily'], '0.120960')


def test_request_only_and_flat_surcharge_match_configured_price_semantics():
    plan = paid_plan(models=["m1"])
    plan["pricing"] = {"*": {"request": "0.001"}}
    CHECK.assertEqual(forecast(plan)['cost_usd']['daily'], '0.288000')
    plan["pricing"]["*"]["input"] = "2"
    plan["pricing"]["*"]["output"] = "8"
    CHECK.assertEqual(forecast(plan)['cost_usd']['daily'], '0.391680')


def test_partial_token_pricing_stays_unknown():
    plan = paid_plan()
    plan["pricing"] = {"*": {"input": 1}}
    CHECK.assertTrue(forecast(plan)['cost_usd']['daily'] is None)


def test_decimal_total_is_rounded_up_only_after_aggregation():
    plan = paid_plan(models=["m1", "m2"], key_count=1, probes_per_interval=1,
                     interval_minutes=1440, input_token_cap=1, output_token_cap=0)
    plan["pricing"] = {"*": {"input": "0.4", "output": 0}}
    CHECK.assertEqual(forecast(plan)['cost_usd'], {'daily': '0.000001', 'month': '0.000024', 'max_run': '0.000001'})
    CHECK.assertTrue(forecast(plan, max_cost_usd='0.0000007')['limits']['ok'] is False)


def test_half_open_bounds_are_provider_wide_not_multiplied_by_keys():
    plan = paid_plan(kind="half_open", calls_per_day=12, max_run_calls=2)
    report = forecast(plan)
    CHECK.assertEqual(report['calls'], {'daily': 12, 'month': 360, 'max_run': 2})
    CHECK.assertEqual(report['components'][0]['kind'], 'half_open')
    CHECK.assertEqual(report['cost_usd']['daily'], '0.004320')


def test_half_open_uses_most_expensive_model_and_unknown_candidate():
    plan = paid_plan(kind="half_open", calls_per_day=10, max_run_calls=1)
    plan["pricing"] = {"openai:m1": {"request": "0.01"}, "openai:m2": {"request": "0.02"}}
    CHECK.assertEqual(forecast(plan)['cost_usd']['daily'], '0.200000')
    del plan["pricing"]["openai:m2"]
    CHECK.assertTrue(forecast(plan)['cost_usd']['daily'] is None)


def test_unbounded_half_open_volume_is_unknown_not_concurrency_times_frequency():
    report = forecast(paid_plan(kind="half_open"), max_calls=100000)
    CHECK.assertTrue(report['calls']['daily'] is None)
    CHECK.assertTrue(report['calls']['max_run'] is None)
    CHECK.assertTrue(report['limits']['ok'] is False)
    CHECK.assertTrue(report['incomplete'] is True)


def test_default_and_disabled_plans_do_not_enable_any_work(monkeypatch):
    monkeypatch.setenv("HEALTH_CHECKS_WAKE", "true")
    monkeypatch.setenv("MODEL_PRICING_USD_PER_MILLION", '{"*":{"request":999}}')
    CHECK.assertEqual(forecast({})['calls']['daily'], 0)
    plan = paid_plan(enabled=False)
    del plan["pricing"]
    report = forecast(plan, max_calls=0, max_cost_usd="0")
    CHECK.assertEqual(report['cost_usd']['daily'], '0.000000')
    CHECK.assertTrue(report['limits']['ok'] is True)


@pytest.mark.parametrize("field,value", [("key_count", -1), ("key_count", True),
    ("input_token_cap", 10**100), ("output_token_cap", 1.5), ("interval_minutes", 0),
    ("probes_per_interval", "2"), ("enabled", "false"), ("models", []),
    ("models", ["m1", "m1"]), ("models", ["openai:m1"])])
def test_invalid_or_overflowing_plan_rejected(field, value):
    with pytest.raises(PlanError):
        forecast(paid_plan(**{field: value}))


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-1", "1e1000000", True, None])
def test_invalid_prices_are_rejected(value):
    plan = paid_plan()
    plan["pricing"] = {"*": {"input": value, "output": 0}}
    with pytest.raises(PlanError):
        forecast(plan)


def test_overflowing_products_rejected_without_iteration_over_calls():
    with pytest.raises(PlanError):
        forecast(paid_plan(key_count=10**9, probes_per_interval=10**9, interval_minutes=1))


def test_no_http_env_storage_or_input_mutation(monkeypatch):
    import config
    import requests
    import socket
    import sqlite3

    def forbidden(*args, **kwargs):
        pytest.fail("forecast attempted external I/O")

    monkeypatch.setattr(config, "load_runtime_env", forbidden)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    plan = paid_plan()
    original = copy.deepcopy(plan)
    forecast(plan)
    CHECK.assertEqual(plan, original)


def cli(plan, *args):
    output = io.StringIO()
    code = main(list(args), stdin=io.StringIO(json.dumps(plan)), stdout=output)
    return code, json.loads(output.getvalue())


def test_cli_limits_apply_to_max_run_and_unknown_cost_fails_closed():
    CHECK.assertEqual(cli(paid_plan(), '--max-calls', '24', '--max-cost-usd', '0.008640')[0], 0)
    CHECK.assertEqual(cli(paid_plan(), '--max-calls', '23')[0], 1)
    CHECK.assertEqual(cli(paid_plan(), '--max-cost-usd', '0.0086399999')[0], 1)
    CHECK.assertEqual(cli(scheduled_plan(), '--max-cost-usd', '10')[0], 1)
    CHECK.assertEqual(cli(paid_plan(kind='half_open'), '--max-calls', '10000')[0], 1)


def test_cli_file_stdin_and_entry_point(tmp_path):
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(paid_plan()), encoding="utf-8")
    code, body = cli({}, "--plan-json", str(path))
    CHECK.assertEqual(code, 0)
    CHECK.assertEqual(body['calls']['daily'], 576)
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, "-I", str(root / "scripts/probe_cost_forecast.py"),
                             "--plan-json", "-"], input="{}", text=True, capture_output=True,
                            cwd=root, check=False)
    CHECK.assertEqual(result.returncode, 0)
    CHECK.assertTrue(json.loads(result.stdout)['zero_generation'] is True)


@pytest.mark.parametrize("payload", ["{", "[]", "{\"days\":NaN}",
    '{"days":1,"days":2}', '{"api_key":"private-sentinel"}',
    '{"schedule":{"execute":true}}'])
def test_cli_invalid_input_is_safe_json(payload):
    output = io.StringIO()
    CHECK.assertEqual(main([], stdin=io.StringIO(payload), stdout=output), 2)
    body = json.loads(output.getvalue())
    CHECK.assertEqual(body['error']['code'], 'invalid_probe_plan')
    CHECK.assertTrue('private-sentinel' not in output.getvalue())


def test_cli_has_no_execution_flag(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--execute"])
    CHECK.assertEqual(error.value.code, 2)


def test_secret_paths_are_rejected_before_reading(tmp_path):
    path = tmp_path / ".env"
    output = io.StringIO()
    CHECK.assertEqual(main(['--plan-json', str(path)], stdout=output), 2)
    CHECK.assertEqual(json.loads(output.getvalue())['error']['code'], 'invalid_probe_plan')


@pytest.mark.parametrize("model", ["vendor/model:thinking", "vendor/model:free"])
def test_native_model_suffixes_are_preserved(model):
    plan = paid_plan(models=[model])
    plan["pricing"] = {"openai:" + model: {"request": "0.01"}}
    report = forecast(plan)
    CHECK.assertEqual(report["components"][0]["models"], [model])
    CHECK.assertEqual(report["cost_usd"]["daily"], "2.880000")


def test_monthly_schedule_uses_direct_horizon_and_partial_half_open_bounds():
    plan = scheduled_plan(interval_minutes=7)
    plan["days"] = 30
    CHECK.assertEqual(forecast(plan)["calls"]["month"], 2470)
    plan = paid_plan(kind="half_open", max_run_calls=2)
    report = forecast(plan, max_calls=2, max_cost_usd="0.01")
    CHECK.assertTrue(report["limits"]["ok"])
    CHECK.assertTrue(report["incomplete"])
    CHECK.assertTrue(report["cost_usd"]["daily"] is None)
    CHECK.assertEqual(report["cost_usd"]["max_run"], "0.000720")


@pytest.mark.parametrize("plan", [None, [], {"probes": [{"kind": []}]},
    {"days": -1}, {"days": True}, {"version": 2}, {"run_minutes": 0},
    {"schedule": {"interval_minutes": 4}}, {"pricing": {"*":[1]}},
    {"routes": [{"id": "auto:a", "candidates": ["openai:m"]}]},
    {"pricing": {"OPENAI:M": {"request": 0}, "openai:m": {"request": 0}}}])
def test_invalid_structures_fail_deliberately(plan):
    with pytest.raises(PlanError):
        forecast(plan)


def test_cli_size_bound_and_missing_file_fail_without_leaking_details(tmp_path):
    output = io.StringIO()
    CHECK.assertEqual(main([], stdin=io.StringIO(" " * (1048576 + 1)), stdout=output), 2)
    output = io.StringIO()
    path = tmp_path / "private-sentinel.json"
    CHECK.assertEqual(main(["--plan-json", str(path)], stdout=output), 2)
    CHECK.assertTrue("private-sentinel" not in output.getvalue())
