"""Deterministic hunt workflow state machine."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class HuntState(StrEnum):
    """Workflow states defined by specification section 5."""

    CREATED = "created"
    DISCOVERING = "discovering"
    PLAN_DRAFT = "plan_draft"
    AWAITING_PLAN_REVIEW = "awaiting_plan_review"
    APPROVED = "approved"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    SYNTHESIZING = "synthesizing"
    REPORT_DRAFT = "report_draft"
    FINALIZED = "finalized"
    CANCELLED = "cancelled"
    FAILED = "failed"


# ``WorkflowState`` is a common name in callers and remains an alias rather
# than a second enum so equality and serialization are unambiguous.
WorkflowState = HuntState


class PausedResumeTarget(StrEnum):
    """Safe state to resume after a recoverable interruption."""

    RUNNING = "running"
    SYNTHESIZING = "synthesizing"


class InvalidStateTransition(ValueError):
    """Raised when a requested hunt state transition is not permitted."""

    def __init__(self, current: HuntState, target: HuntState) -> None:
        super().__init__(f"invalid hunt state transition: {current.value} -> {target.value}")
        self.current = current
        self.target = target


TERMINAL_STATES: Final[frozenset[HuntState]] = frozenset(
    {HuntState.FINALIZED, HuntState.CANCELLED, HuntState.FAILED}
)

# The explicit table follows the specification's allowed moves.  Cancellation
# and unrecoverable failures are added below as separate deterministic rules.
_EXPLICIT_TRANSITIONS: Final[dict[HuntState, frozenset[HuntState]]] = {
    HuntState.CREATED: frozenset({HuntState.DISCOVERING}),
    HuntState.DISCOVERING: frozenset({HuntState.PLAN_DRAFT}),
    HuntState.PLAN_DRAFT: frozenset({HuntState.AWAITING_PLAN_REVIEW}),
    HuntState.AWAITING_PLAN_REVIEW: frozenset(
        {HuntState.APPROVED, HuntState.PLAN_DRAFT}
    ),
    HuntState.APPROVED: frozenset({HuntState.QUEUED, HuntState.PLAN_DRAFT}),
    HuntState.QUEUED: frozenset(
        {HuntState.PLAN_DRAFT, HuntState.RUNNING, HuntState.SYNTHESIZING}
    ),
    HuntState.RUNNING: frozenset({HuntState.SYNTHESIZING, HuntState.PAUSED}),
    HuntState.PAUSED: frozenset({HuntState.QUEUED}),
    HuntState.SYNTHESIZING: frozenset({HuntState.REPORT_DRAFT, HuntState.PAUSED}),
    HuntState.REPORT_DRAFT: frozenset({HuntState.FINALIZED}),
    HuntState.FINALIZED: frozenset(),
    HuntState.CANCELLED: frozenset(),
    HuntState.FAILED: frozenset(),
}

# Public immutable view used by transition validators and tests.  It includes
# cancellation from every non-terminal state and failure from active states.
ALLOWED_TRANSITIONS: Final[dict[HuntState, frozenset[HuntState]]] = {
    state: frozenset(
        set(targets)
        | ({HuntState.CANCELLED} if state not in TERMINAL_STATES else set())
        | (
            {HuntState.FAILED}
            if state not in {HuntState.CREATED, *TERMINAL_STATES}
            else set()
        )
    )
    for state, targets in _EXPLICIT_TRANSITIONS.items()
}


def is_terminal_state(state: HuntState | str) -> bool:
    """Return whether a workflow state is terminal."""

    return HuntState(state) in TERMINAL_STATES


def allowed_next_states(state: HuntState | str) -> frozenset[HuntState]:
    """Return the immutable set of permitted targets for ``state``."""

    return ALLOWED_TRANSITIONS[HuntState(state)]


def can_transition(current: HuntState | str, target: HuntState | str) -> bool:
    """Check a transition without mutating any state."""

    current_state, target_state = HuntState(current), HuntState(target)
    # Repeated cancellation is explicitly idempotent.
    if current_state is HuntState.CANCELLED and target_state is HuntState.CANCELLED:
        return True
    return target_state in ALLOWED_TRANSITIONS[current_state]


def validate_transition(current: HuntState | str, target: HuntState | str) -> None:
    """Raise :class:`InvalidStateTransition` when a move is not allowed."""

    current_state, target_state = HuntState(current), HuntState(target)
    if not can_transition(current_state, target_state):
        raise InvalidStateTransition(current_state, target_state)


@dataclass
class HuntStateMachine:
    """Mutable in-memory representation of one hunt's workflow state.

    Persistence layers should save the resulting state atomically.  This class
    only enforces transition rules and never performs external side effects.
    """

    state: HuntState = HuntState.CREATED
    resume_target: PausedResumeTarget | None = None

    def __post_init__(self) -> None:
        """Normalize enum-like constructor values and validate pause metadata."""

        self.state = HuntState(self.state)
        if self.resume_target is not None:
            self.resume_target = PausedResumeTarget(self.resume_target)
        if self.state is not HuntState.PAUSED and self.resume_target is not None:
            raise ValueError("resume_target is only valid while state is paused")

    @property
    def is_terminal(self) -> bool:
        """Whether the current state cannot progress further."""

        return is_terminal_state(self.state)

    def can_transition(self, target: HuntState | str) -> bool:
        """Check a target against this machine, including pause metadata."""

        target_state = HuntState(target)
        if not can_transition(self.state, target_state):
            return False
        if self.state is HuntState.QUEUED and target_state in {
            HuntState.RUNNING,
            HuntState.SYNTHESIZING,
        }:
            if self.resume_target is not None:
                return target_state.value == self.resume_target.value
            if target_state is HuntState.SYNTHESIZING:
                # queued -> synthesizing is reserved for a synthesis resume.
                return False
        return True

    def transition(
        self,
        target: HuntState | str,
        *,
        resume_target: PausedResumeTarget | str | None = None,
    ) -> HuntState:
        """Apply one validated transition and return the resulting state.

        Cancellation is idempotent: applying ``cancelled`` to an already
        cancelled hunt is a no-op and returns ``cancelled``.
        """

        target_state = HuntState(target)
        if self.state is HuntState.CANCELLED and target_state is HuntState.CANCELLED:
            return self.state
        if not self.can_transition(target_state):
            raise InvalidStateTransition(self.state, target_state)

        if self.state is HuntState.RUNNING and target_state is HuntState.PAUSED:
            self.resume_target = PausedResumeTarget.RUNNING
        elif self.state is HuntState.SYNTHESIZING and target_state is HuntState.PAUSED:
            self.resume_target = PausedResumeTarget.SYNTHESIZING
        elif self.state is HuntState.PAUSED and target_state is HuntState.QUEUED:
            if resume_target is not None and PausedResumeTarget(resume_target) is not self.resume_target:
                raise ValueError("resume_target does not match paused hunt metadata")
        elif self.state is HuntState.QUEUED and target_state is HuntState.SYNTHESIZING:
            # The caller may explicitly identify the resumed synthesis target
            # when constructing a queued record.
            if resume_target is not None and PausedResumeTarget(resume_target) is not PausedResumeTarget.SYNTHESIZING:
                raise ValueError("queued synthesis requires a synthesizing resume target")
        elif target_state in TERMINAL_STATES or target_state in {
            HuntState.RUNNING,
            HuntState.SYNTHESIZING,
        }:
            self.resume_target = None

        self.state = target_state
        return self.state


# Common alternate name used by persistence code.
HuntWorkflow = HuntStateMachine

