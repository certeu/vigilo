"""Simplified grey-box workflow — single-agent pipeline for OpenCode/local LLMs.

Replaces the full 4-phase scheduler-driven pipeline with a streamlined
3-phase approach suited for smaller models (e.g. Qwen 3.6 via OpenCode):

  Phase 1: Preflight + Managed Scans (same infra, no discovery agent)
  Phase 2: Single "pentest" agent (discovery + testing + report in one session)
  Phase 3: Graph export

No scheduler, no specialist dispatch, no chain detection, no session pool.
All activities are reused from the full pipeline — no new activity code.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from src.greybox.temporal.activities import (
        AgentExecutionInput,
        AuditEventInput,
        BuildPromptInput,
        ExportGraphInput,
        GreyBoxActivityInput,
        InitGraphInput,
        InitWorkspaceInput,
        ManagedScanInput,
        ResolveContextInput,
        authenticate_sessions,
        build_agent_prompt,
        export_graph,
        init_graph,
        init_workspace,
        resolve_agent_context,
        run_greybox_agent,
        run_managed_scan,
        write_audit_event,
    )
    from src.greybox.types.config import GreyBoxConfig, GreyBoxInput

_NON_RETRYABLE_TYPES: list[str] = [
    "AuthenticationError",
    "BudgetExhaustedError",
    "ConfigurationError",
    "ExecutionError",
    "ExecutionLimitError",
    "InvalidRequestError",
    "InvalidTargetError",
    "PermissionError",
    "RequestTooLargeError",
    "ScannerNotFoundError",
    "SchemaVersionMismatchError",
]

PREFLIGHT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=10),
    maximum_interval=timedelta(minutes=1),
    backoff_coefficient=2.0,
    maximum_attempts=3,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

AGENT_RETRY = RetryPolicy(
    initial_interval=timedelta(minutes=1),
    maximum_interval=timedelta(minutes=5),
    backoff_coefficient=2.0,
    maximum_attempts=3,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

_AGENT_START_TO_CLOSE = timedelta(hours=4)
_AGENT_HEARTBEAT = timedelta(minutes=60)
_UTILITY_START_TO_CLOSE = timedelta(minutes=5)
_PREFLIGHT_START_TO_CLOSE = timedelta(minutes=2)


@workflow.defn
class GreyBoxSimplifiedWorkflow:
    """Simplified 3-phase grey-box pipeline for local LLMs via OpenCode."""

    def __init__(self) -> None:
        self.current_phase: str = "phase_1"
        self.done: bool = False
        self.error: str | None = None
        self.total_cost: float = 0.0
        self.findings_count: int = 0

    @workflow.query
    def get_progress(self) -> dict[str, Any]:
        return {
            "phase": self.current_phase,
            "done": self.done,
            "error": self.error,
            "total_cost": self.total_cost,
            "findings_count": self.findings_count,
        }

    async def _audit(self, workspace: str, **kwargs: object) -> None:
        try:
            await workflow.execute_activity(
                write_audit_event,
                AuditEventInput(workspace=workspace, **kwargs),
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=PREFLIGHT_RETRY,
            )
        except Exception as exc:
            workflow.logger.warning("Audit event failed: %s", exc)

    @workflow.run
    async def run(self, input: GreyBoxInput) -> dict[str, Any]:
        config = input.config
        start_time = workflow.now()

        resolved_output = input.output_path or f".vigilo/{input.session_id}"
        base_input = GreyBoxActivityInput(
            web_url=input.web_url,
            session_id=input.session_id,
            credentials_path=input.credentials_path,
            config_path=input.config_path,
            output_path=resolved_output,
            description=input.description,
            rules_avoid=input.rules_avoid,
            rules_focus=input.rules_focus,
        )
        workspace = resolved_output

        try:
            # =============================================================
            # Phase 1: Preflight + Managed Scans
            # =============================================================
            if self.current_phase == "phase_1":
                await self._audit(workspace, event_type="phase_start", phase="phase_1")
                await self._phase_1_preflight_scans(base_input, config)
                await self._audit(workspace, event_type="phase_complete", phase="phase_1")
                self.current_phase = "phase_2"

            # =============================================================
            # Phase 2: Single Pentest Agent
            # =============================================================
            if self.current_phase == "phase_2":
                await self._audit(workspace, event_type="phase_start", phase="phase_2")
                await self._phase_2_pentest_agent(base_input, config)
                await self._audit(workspace, event_type="phase_complete", phase="phase_2")
                self.current_phase = "phase_3"

            # =============================================================
            # Phase 3: Graph Export
            # =============================================================
            if self.current_phase == "phase_3":
                await self._audit(workspace, event_type="phase_start", phase="phase_3")
                await self._phase_3_export(base_input)
                await self._audit(workspace, event_type="phase_complete", phase="phase_3")

            self.done = True
            self.current_phase = "completed"

            elapsed_ms = int((workflow.now() - start_time).total_seconds() * 1000)
            await self._audit(
                workspace,
                event_type="finalize",
                status="completed",
                total_duration_ms=elapsed_ms,
                total_cost=self.total_cost,
                findings_count=self.findings_count,
            )
            return self.get_progress()

        except Exception as e:
            self.error = str(e)[:2000]
            self.done = True
            workflow.logger.error("Simplified pipeline failed: %s", self.error)

            elapsed_ms = int((workflow.now() - start_time).total_seconds() * 1000)
            await self._audit(
                workspace,
                event_type="finalize",
                status="failed",
                total_duration_ms=elapsed_ms,
                total_cost=self.total_cost,
                findings_count=self.findings_count,
                error=self.error,
            )
            raise

    # -------------------------------------------------------------------
    # Phase 1: Preflight + Managed Scans (no discovery agent)
    # -------------------------------------------------------------------

    async def _phase_1_preflight_scans(
        self,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
    ) -> None:
        workflow.logger.info("Phase 1: Preflight + Managed Scans (simplified)")

        await workflow.execute_activity(
            init_graph,
            InitGraphInput(
                session_id=base_input.session_id,
                credentials_path=base_input.credentials_path,
                web_url=base_input.web_url,
            ),
            start_to_close_timeout=_PREFLIGHT_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        await workflow.execute_activity(
            init_workspace,
            InitWorkspaceInput(
                session_id=base_input.session_id,
                web_url=base_input.web_url,
                output_path=base_input.output_path,
            ),
            start_to_close_timeout=_PREFLIGHT_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        auth_result = await workflow.execute_activity(
            authenticate_sessions,
            base_input,
            start_to_close_timeout=_AGENT_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )
        cookie_paths: dict[str, str] = (auth_result or {}).get("cookie_paths", {}) or {}
        scan_identity: str | None = None
        scan_session_file: str | None = None
        if cookie_paths:
            if config.default_identity in cookie_paths:
                scan_identity = config.default_identity
            else:
                scan_identity = next(iter(cookie_paths))
            scan_session_file = cookie_paths[scan_identity]

        # Run all enabled managed scans in parallel
        enabled_scans = [
            name for name, enabled in config.managed_scans.items() if enabled
        ]
        if enabled_scans:
            semaphore = asyncio.Semaphore(config.managed_scan_concurrency)

            async def _run_one(scan_name: str) -> Any:
                async with semaphore:
                    return await workflow.execute_activity(
                        run_managed_scan,
                        ManagedScanInput(
                            web_url=base_input.web_url,
                            session_id=base_input.session_id,
                            scan_type=scan_name,
                            output_dir=base_input.output_path,
                            identity_name=scan_identity or "",
                            session_file=scan_session_file or "",
                        ),
                        start_to_close_timeout=_AGENT_START_TO_CLOSE,
                        heartbeat_timeout=_AGENT_HEARTBEAT,
                        retry_policy=AGENT_RETRY,
                        activity_id=f"managed-scan:{scan_name}",
                    )

            results = await asyncio.gather(
                *(_run_one(name) for name in enabled_scans),
                return_exceptions=True,
            )
            for i, result in enumerate(results):
                scan_name = enabled_scans[i]
                if isinstance(result, BaseException):
                    workflow.logger.warning(
                        "Managed scan %s failed: %s", scan_name, str(result)[:500]
                    )
                elif isinstance(result, dict):
                    self.total_cost += result.get("cost_usd", 0.0)

    # -------------------------------------------------------------------
    # Phase 2: Single Pentest Agent
    # -------------------------------------------------------------------

    async def _phase_2_pentest_agent(
        self,
        base_input: GreyBoxActivityInput,
        config: GreyBoxConfig,
    ) -> None:
        workflow.logger.info("Phase 2: Single pentest agent (simplified)")

        agent_id = f"pentest-{str(workflow.uuid4())[:8]}"

        ctx = await workflow.execute_activity(
            resolve_agent_context,
            ResolveContextInput(
                session_id=base_input.session_id,
                credentials_path=base_input.credentials_path,
                web_url=base_input.web_url,
                target="{}",
                budget_remaining_pct=1.0,
            ),
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        rules_avoid = "\n".join(f"- {r}" for r in base_input.rules_avoid) if base_input.rules_avoid else ""
        rules_focus = "\n".join(f"- {r}" for r in base_input.rules_focus) if base_input.rules_focus else ""

        prompt_result = await workflow.execute_activity(
            build_agent_prompt,
            BuildPromptInput(
                web_url=base_input.web_url,
                session_id=base_input.session_id,
                agent_name=agent_id,
                prompt_template="greybox/pentest",
                description=base_input.description,
                rules_avoid=rules_avoid,
                rules_focus=rules_focus,
                playwright_session="agent1",
                output_path=base_input.output_path or "",
                graph_summary=ctx.get("graph_summary", ""),
                identities=ctx.get("identities", ""),
                identities_block=ctx.get("identities_block", ""),
                identity_count=ctx.get("identity_count", ""),
                login_instructions=ctx.get("login_instructions", ""),
                budget_status=ctx.get("budget_status", ""),
            ),
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=PREFLIGHT_RETRY,
        )

        prompt = (
            prompt_result
            if isinstance(prompt_result, str)
            else prompt_result.get("prompt", "")
        )

        workspace_cwd = (
            base_input.output_path
            if base_input.output_path and base_input.output_path.startswith("/")
            else f"/app/{base_input.output_path}"
            if base_input.output_path
            else "/app"
        )

        result = await workflow.execute_activity(
            run_greybox_agent,
            AgentExecutionInput(
                web_url=base_input.web_url,
                session_id=base_input.session_id,
                agent_name=agent_id,
                prompt=prompt,
                model_tier=config.specialist_model,
                cwd=workspace_cwd,
                output_path=base_input.output_path or "",
            ),
            start_to_close_timeout=_AGENT_START_TO_CLOSE,
            heartbeat_timeout=_AGENT_HEARTBEAT,
            retry_policy=AGENT_RETRY,
            activity_id=f"agent:{agent_id}",
        )

        if isinstance(result, dict):
            self.total_cost += result.get("cost_usd", 0.0)
            findings = result.get("findings", [])
            self.findings_count = len(findings) if findings else 0

    # -------------------------------------------------------------------
    # Phase 3: Graph Export
    # -------------------------------------------------------------------

    async def _phase_3_export(self, base_input: GreyBoxActivityInput) -> None:
        workflow.logger.info("Phase 3: Graph export (simplified)")

        try:
            await workflow.execute_activity(
                export_graph,
                ExportGraphInput(
                    session_id=base_input.session_id,
                    output_path=base_input.output_path,
                ),
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=PREFLIGHT_RETRY,
            )
        except Exception as exc:
            workflow.logger.warning("Graph export failed (non-fatal): %s", exc)
