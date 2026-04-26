"""Abstract backend interface."""
from __future__ import annotations

from dataclasses import dataclass, field

from auto_xdp.state import AppliedState, DesiredState, ObservedState, ReconcilePlan, compute_reconcile_plan


@dataclass
class BackendStatus:
    name: str
    available: bool
    reason: str = ""
    details: dict[str, str] = field(default_factory=dict)
    checks: dict[str, bool] = field(default_factory=dict)

    @property
    def failed_checks(self) -> list[str]:
        return [name for name, passed in self.checks.items() if not passed]

    def format_message(self) -> str:
        parts: list[str] = []
        if self.reason:
            parts.append(self.reason)
        if self.failed_checks:
            parts.append(f"failed checks: {', '.join(self.failed_checks)}")
        if self.details:
            parts.append(", ".join(f"{key}={value}" for key, value in self.details.items()))
        if parts:
            return "; ".join(parts)
        return "available" if self.available else "unavailable"


class PortBackend:
    name = "backend"

    @classmethod
    def probe(cls) -> BackendStatus:
        return BackendStatus(name=cls.name, available=True)

    def get_applied_state(self) -> AppliedState:
        raise NotImplementedError

    def build_reconcile_plan(self, desired_state: DesiredState, applied_state: AppliedState) -> ReconcilePlan:
        return compute_reconcile_plan(desired_state, applied_state)

    def apply_reconcile_plan(
        self,
        plan: ReconcilePlan,
        dry_run: bool,
        desired_state: DesiredState,
        observed_state: ObservedState | None = None,
    ) -> None:
        raise NotImplementedError

    def reconcile(
        self,
        desired_state: DesiredState,
        dry_run: bool,
        observed_state: ObservedState | None = None,
    ) -> None:
        applied_state = self.get_applied_state()
        plan = self.build_reconcile_plan(desired_state, applied_state)
        self.apply_reconcile_plan(plan, dry_run, desired_state, observed_state)

    def close(self) -> None:
        return None
