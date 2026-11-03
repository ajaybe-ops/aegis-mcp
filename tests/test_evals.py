"""Offline evaluation suite: happy paths, failure semantics, and CLI wiring."""

from __future__ import annotations

import asyncio
import json

from aegis_mcp.evals import runner


def test_eval_suite_passes_all_scenarios() -> None:
    results = asyncio.run(runner.run_suite())
    assert results, "evaluation suite ran no scenarios"
    assert len(results) == len(runner.SCENARIOS)
    failures = [result for result in results if not result.passed]
    assert failures == []
    print(f"\n{len(results)} evaluation scenarios completed")


def test_eval_failure_is_recorded_with_detail() -> None:
    async def failing(_session) -> None:  # type: ignore[no-untyped-def]
        raise AssertionError("boom")

    scenario = runner.Scenario(name="boom", description="deliberate failure", fn=failing)
    result = asyncio.run(runner._run_scenario(scenario))
    assert result.passed is False
    assert result.detail


def test_eval_json_cli_aggregates_results(capsys) -> None:
    code = runner.main(["--json"])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == len(runner.SCENARIOS)
    assert payload["passed"] == len(runner.SCENARIOS)
