"""Deterministic tests for hunt workflow transitions."""

from __future__ import annotations

import pytest

from threat_hunting.domain.state import (
    HuntState,
    HuntStateMachine,
    InvalidStateTransition,
    PausedResumeTarget,
    can_transition,
)


def test_happy_path_allows_only_the_declared_workflow_moves() -> None:
    machine = HuntStateMachine()
    for state in (
        HuntState.DISCOVERING,
        HuntState.PLAN_DRAFT,
        HuntState.AWAITING_PLAN_REVIEW,
        HuntState.APPROVED,
        HuntState.QUEUED,
        HuntState.RUNNING,
        HuntState.SYNTHESIZING,
        HuntState.REPORT_DRAFT,
        HuntState.FINALIZED,
    ):
        assert machine.transition(state) is state
    assert machine.is_terminal


def test_rejected_transition_does_not_mutate_state() -> None:
    machine = HuntStateMachine(HuntState.PLAN_DRAFT)
    with pytest.raises(InvalidStateTransition):
        machine.transition(HuntState.RUNNING)
    assert machine.state is HuntState.PLAN_DRAFT

    assert not can_transition(HuntState.CREATED, HuntState.RUNNING)


def test_pause_metadata_controls_safe_resume_target() -> None:
    machine = HuntStateMachine(HuntState.RUNNING)
    machine.transition(HuntState.PAUSED)
    assert machine.resume_target is PausedResumeTarget.RUNNING
    machine.transition(HuntState.QUEUED)
    machine.transition(HuntState.RUNNING)

    machine.transition(HuntState.PAUSED)
    machine.transition(HuntState.QUEUED)
    with pytest.raises(InvalidStateTransition):
        machine.transition(HuntState.SYNTHESIZING)


def test_synthesis_pause_can_resume_synthesis_only() -> None:
    machine = HuntStateMachine(HuntState.SYNTHESIZING)
    machine.transition(HuntState.PAUSED)
    assert machine.resume_target is PausedResumeTarget.SYNTHESIZING
    machine.transition(HuntState.QUEUED)
    machine.transition(HuntState.SYNTHESIZING)


def test_cancellation_is_allowed_from_nonterminal_states_and_idempotent() -> None:
    machine = HuntStateMachine(HuntState.CREATED)
    machine.transition(HuntState.CANCELLED)
    assert machine.transition(HuntState.CANCELLED) is HuntState.CANCELLED
    assert machine.state is HuntState.CANCELLED
    with pytest.raises(InvalidStateTransition):
        machine.transition(HuntState.CREATED)

