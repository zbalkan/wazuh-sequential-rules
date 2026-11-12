"""Runtime behaviour of rule C: earlier rule A, then current rule B.

The contract is the Wazuh logtest daemon of a manager provisioned by
wazuhdevenv, reached through wazuhtester. Expected values come from the
article and from analysisd v4.14.10 (rules.c, eventinfo.c): rule C matches on
B's event when a match of rule A with the same decoded srcip and the same
agent is retained within the last 60 seconds. Each logtest session loads its
own ruleset and keeps its own history, so every test owns its state.
"""

from __future__ import annotations

import time

import pytest
from wazuhtester import (
    LogtestResponse,
    LogtestSession,
    LogtestStatus,
    send_multiple_logs,
)

pytestmark = pytest.mark.wazuh_logtest

RULE_A = "100570"  # suspicious authentication attempt
RULE_B = "100505"  # successful authentication
RULE_C = "100575"  # the article's correlation rule

RULE_C_LEVEL = 12  # level="12"
RULE_C_TIMEFRAME_SECONDS = 60  # timeframe="60"

SOURCE_IP = "203.0.113.10"
OTHER_IP = "198.51.100.20"


def suspicious(srcip: str = SOURCE_IP) -> str:
    """An event that matches rule A."""
    return f"Nov 12 17:00:00 lab seqdemo: action=suspicious srcip={srcip}"


def success(srcip: str = SOURCE_IP) -> str:
    """An event that matches rule B."""
    return f"Nov 12 17:00:05 lab seqdemo: action=success srcip={srcip}"


def rule_ids(responses: list[LogtestResponse]) -> list[str | None]:
    return [response.rule_id for response in responses]


@pytest.mark.parametrize(
    ("logs", "expected"),
    [
        pytest.param([success()], [RULE_B], id="B without a prior A"),
        pytest.param([suspicious()], [RULE_A], id="A without a following B"),
        pytest.param(
            [suspicious(), success()], [RULE_A, RULE_C], id="A then B, same srcip"
        ),
        pytest.param(
            [success(), suspicious()], [RULE_B, RULE_A], id="B then A"
        ),
        pytest.param(
            [suspicious(SOURCE_IP), success(OTHER_IP)],
            [RULE_A, RULE_B],
            id="A then B, different srcip",
        ),
        # Omitted frequency is stored as zero: one retained A is enough.
        pytest.param(
            [suspicious(), suspicious(), success()],
            [RULE_A, RULE_A, RULE_C],
            id="A then A then B",
        ),
        # At internal frequency zero the search marks only the current event,
        # so the same A remains available to a second B (eventinfo.c).
        pytest.param(
            [suspicious(), success(), success()],
            [RULE_A, RULE_C, RULE_C],
            id="A then B then B",
        ),
    ],
)
def test_sequence_outcome(logs: list[str], expected: list[str]) -> None:
    responses = send_multiple_logs(logs)

    assert rule_ids(responses) == expected, f"logs: {logs}"


def test_correlation_reports_rule_c_metadata() -> None:
    responses = send_multiple_logs([suspicious(), success()])
    correlated = responses[-1]

    assert correlated.status == LogtestStatus.RuleMatch
    assert correlated.rule_id == RULE_C
    assert correlated.rule_level == RULE_C_LEVEL
    # Two <description> elements are concatenated; $(srcip) is B's srcip.
    assert correlated.rule_description == (
        f"Correlated events from {SOURCE_IP}. Potential password spraying."
    )
    assert correlated.rule_mitre_ids == {"T1110"}
    assert "password_spray" in correlated.rule_groups


def test_correlation_requires_same_agent_by_default() -> None:
    # Two locations in the agent format share one daemon session through its
    # token, so A and B differ only in agent identity.
    with LogtestSession(location="[001] (agent-a) any->seqdemo") as agent_a, \
            LogtestSession(location="[002] (agent-b) any->seqdemo") as agent_b:
        first_reply = agent_a.process_log(suspicious())
        token = first_reply["data"]["token"]
        second_reply = agent_b.process_log(success(), token=token)

    responses = [LogtestResponse(first_reply), LogtestResponse(second_reply)]

    assert rule_ids(responses) == [RULE_A, RULE_B]


@pytest.mark.slow
def test_a_older_than_timeframe_does_not_correlate() -> None:
    # Deliberate fixed sleep: Search_LastSids compares retained matches with
    # the manager's wall clock, which a test cannot inject. Two seconds past
    # the boundary avoids the inclusive comparison at exactly 60 seconds.
    with LogtestSession() as session:
        first = LogtestResponse(session.process_log(suspicious()))
        time.sleep(RULE_C_TIMEFRAME_SECONDS + 2)
        second = LogtestResponse(session.process_log(success()))

    assert rule_ids([first, second]) == [RULE_A, RULE_B]
