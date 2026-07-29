"""Temporal workflow for Shannon Python pentest pipeline.

Orchestrates the 7-phase penetration testing pipeline:
  Phase 1: Preflight       — validate repo, config, target reachability
  Phase 2: Pre-Recon       — code analysis (Opus)
  Phase 3: Recon           — active reconnaissance (Sonnet)
  Phase 4-5: Vuln+Exploit  — 8 pipelined pairs in parallel (with feedback loops)
  Phase 5b: Chain Exploit  — cross-type vulnerability chaining (Opus)
  Phase 6: Remediation     — automated patching (Sonnet)
  Phase 7: Reporting       — evidence assembly + executive summary (Haiku)

Features:
- Queryable state via get_progress
- Automatic retry with backoff for transient/billing errors
- Non-retryable classification for permanent errors
- Conditional agent enablement (GraphQL, WebSocket) based on tech detection
- Feedback loops: exploit agent can request more info from vuln agent (max 1)
- Graceful failure handling: individual pipelines continue if one fails
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    import dataclasses

    from src.temporal.activities import ActivityInput
    from src.types.agents import VulnType
    from src.types.metrics import AgentMetrics, PipelineState, PipelineSummary
    from src.types.stages import resolve_stages

# ---------------------------------------------------------------------------
# Non-retryable error types — shared across all retry policies
# ---------------------------------------------------------------------------

_NON_RETRYABLE_TYPES: list[str] = [
    "AuthenticationError",
    "PermissionError",
    "InvalidRequestError",
    "RequestTooLargeError",
    "ConfigurationError",
    "InvalidTargetError",
    "ExecutionLimitError",
]

# ---------------------------------------------------------------------------
# Retry policies
# ---------------------------------------------------------------------------

PRODUCTION_RETRY = RetryPolicy(
    initial_interval=timedelta(minutes=5),
    maximum_interval=timedelta(minutes=30),
    backoff_coefficient=2.0,
    maximum_attempts=50,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

PREFLIGHT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=10),
    maximum_interval=timedelta(minutes=1),
    backoff_coefficient=2.0,
    maximum_attempts=3,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

# Subscription plans have 5h+ rolling rate limit windows
SUBSCRIPTION_RETRY = RetryPolicy(
    initial_interval=timedelta(minutes=5),
    maximum_interval=timedelta(hours=6),
    backoff_coefficient=2.0,
    maximum_attempts=100,
    non_retryable_error_types=_NON_RETRYABLE_TYPES,
)

# ---------------------------------------------------------------------------
# Activity timeout defaults
# ---------------------------------------------------------------------------

_AGENT_START_TO_CLOSE = timedelta(hours=2)
_REMEDIATION_START_TO_CLOSE = timedelta(hours=4)  # Remediation orchestrates many sub-agents
_AGENT_HEARTBEAT = timedelta(minutes=60)
_UTILITY_START_TO_CLOSE = timedelta(minutes=5)
_PREFLIGHT_START_TO_CLOSE = timedelta(minutes=2)
_REPORT_START_TO_CLOSE = timedelta(minutes=10)

# Vuln types that always run (not conditional on tech detection)
_ALWAYS_RUN_TYPES: list[str] = [
    "injection",
    "xss",
    "auth",
    "ssrf",
    "authz",
    "crypto",
]

# Vuln types that have no dedicated exploit agent
_NO_EXPLOIT_TYPES: set[str] = {"crypto"}


# ---------------------------------------------------------------------------
# Pipeline result types (workflow-internal)
# ---------------------------------------------------------------------------


def _vuln_exploit_result(
    vuln_type: str,
    vuln_metrics: dict[str, Any] | None = None,
    exploit_metrics: dict[str, Any] | None = None,
    exploit_decision: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    """Build a standardized result dict for a vuln+exploit pipeline."""
    return {
        "vuln_type": vuln_type,
        "vuln_metrics": vuln_metrics,
        "exploit_metrics": exploit_metrics,
        "exploit_decision": exploit_decision,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Workflow definition
# ---------------------------------------------------------------------------


@workflow.defn
class PentestPipelineWorkflow:
    """7-phase pentest pipeline orchestrated via Temporal.

    Manages state, retry policies, parallel execution of vuln+exploit
    pipelines, feedback loops, and progress queries.
    """

    def __init__(self) -> None:
        self._state = PipelineState(
            status="running",
            start_time=0.0,
        )
        self._feedback_used: dict[str, bool] = {}
        self._completed_from_resume: set[str] = set()

    # -------------------------------------------------------------------
    # Query handler
    # -------------------------------------------------------------------

    @workflow.query
    def get_progress(self) -> dict[str, Any]:
        """Return current pipeline progress for monitoring."""
        elapsed_ms = int(
            (workflow.now().timestamp() - self._state.start_time) * 1000
        )
        return {
            **self._state.model_dump(),
            "workflow_id": workflow.info().workflow_id,
            "elapsed_ms": elapsed_ms,
        }

    # -------------------------------------------------------------------
    # Main workflow run
    # -------------------------------------------------------------------

    @workflow.run
    async def run(self, input: dict[str, Any]) -> dict[str, Any]:
        """Execute the full 7-phase pipeline.

        Parameters
        ----------
        input:
            Dict matching PipelineInput schema. We accept a dict rather
            than a Pydantic model to ensure clean Temporal serialization.

        Returns
        -------
        dict:
            Final PipelineState as a dict.
        """
        # Initialize state
        self._state.start_time = workflow.now().timestamp()

        # Select retry policy
        pipeline_config = input.get("pipeline_config") or {}
        retry_preset = pipeline_config.get("retry_preset")

        if retry_preset == "subscription":
            retry = SUBSCRIPTION_RETRY
        else:
            retry = PRODUCTION_RETRY

        max_concurrent = pipeline_config.get("max_concurrent_pipelines", 8)

        # Resolve which optional phases run. None → full pipeline (legacy).
        # Invariants (enforced in resolve_stages): exploitation is welded to vuln,
        # and critique always runs — neither can be disabled here.
        stages = resolve_stages(input.get("stages"))
        workflow.logger.info(
            "Stage selection: vuln=%s sca=%s integrity=%s chain=%s critique=%s remediation=%s",
            stages.run_vuln, stages.run_sca, stages.run_integrity,
            stages.run_chain, stages.run_critique, stages.run_remediation,
        )

        # Build ActivityInput dict for passing to activities
        wf_id = input.get("workflow_id") or workflow.info().workflow_id
        session_id = (
            input.get("session_id")
            or input.get("resume_from_workspace")
            or wf_id
        )

        activity_input = ActivityInput(
            web_url=input.get("web_url", ""),
            repo_path=input["repo_path"],
            workflow_id=wf_id,
            session_id=session_id,
            config_path=input.get("config_path"),
            output_path=input.get("output_path"),
        )

        # Handle resume: load completed agents from previous run
        resume_from = input.get("resume_from_workspace")
        if resume_from:
            resume_state = await workflow.execute_activity(
                "load_resume_state",
                args=[activity_input, resume_from],
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=retry,
            )
            if resume_state:
                self._completed_from_resume = set(resume_state.get("completed_agents", []))
                workflow.logger.info(
                    "Resume: %d agents already completed",
                    len(self._completed_from_resume),
                )

        try:
            # ===============================================================
            # Phase 1: Preflight Validation
            # ===============================================================
            self._state.current_phase = "preflight"
            self._state.current_agent = None

            await workflow.execute_activity(
                "preflight_validation",
                args=[activity_input],
                start_to_close_timeout=_PREFLIGHT_START_TO_CLOSE,
                retry_policy=PREFLIGHT_RETRY,
            )
            workflow.logger.info("Preflight validation passed")

            # ===============================================================
            # Phase 2: Pre-Reconnaissance
            # ===============================================================
            await self._run_sequential_phase(
                "pre-recon", "pre-recon", activity_input, retry
            )

            # ===============================================================
            # Phase 2.5: SCA (runs in parallel with Phase 3)
            # ===============================================================
            async def _run_sca() -> None:
                try:
                    await self._run_sequential_phase(
                        "sca", "sca", activity_input, retry
                    )
                except Exception as exc:
                    workflow.logger.warning("SCA agent failed (non-fatal): %s", exc)

            sca_task = asyncio.create_task(_run_sca()) if stages.run_sca else None

            # ===============================================================
            # Phase 2.5b: Integrity Analysis (runs in parallel with Phase 3)
            # ===============================================================
            async def _run_integrity() -> None:
                try:
                    await self._run_sequential_phase(
                        "integrity", "integrity", activity_input, retry
                    )
                except Exception as exc:
                    workflow.logger.warning("Integrity agent failed (non-fatal): %s", exc)

            integrity_task = (
                asyncio.create_task(_run_integrity()) if stages.run_integrity else None
            )

            # ===============================================================
            # Phase 3: Reconnaissance
            # ===============================================================
            await self._run_sequential_phase(
                "recon", "recon", activity_input, retry
            )

            # Collect SCA result (non-fatal)
            if sca_task is not None:
                try:
                    await sca_task
                except Exception as exc:
                    workflow.logger.warning("SCA task failed (non-fatal): %s", exc)

            # Collect integrity result (non-fatal)
            if integrity_task is not None:
                try:
                    await integrity_task
                except Exception as exc:
                    workflow.logger.warning("Integrity task failed (non-fatal): %s", exc)

            # ===============================================================
            # Phases 4-5: Vulnerability Analysis + Exploitation (Pipelined)
            # ===============================================================
            # Read detected technologies for conditional agent enablement
            detected_tech = await workflow.execute_activity(
                "read_detected_technologies",
                args=[activity_input],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            self._state.current_phase = "vulnerability-exploitation"
            self._state.current_agent = "pipelines"

            await self._log_phase(
                activity_input, "vulnerability-exploitation", "start", retry
            )

            # Build pipeline configs (always-run + conditional)
            pipeline_configs = self._build_pipeline_configs(detected_tech)

            # Launch all pipelines concurrently with semaphore throttling
            sem = asyncio.Semaphore(max_concurrent)

            async def _throttled(coro):
                async with sem:
                    return await coro

            pipeline_tasks = [
                _throttled(
                    self._run_vuln_exploit_pipeline(
                        config["vuln_type"], activity_input, retry
                    )
                )
                for config in pipeline_configs
            ]

            # Use asyncio.gather with return_exceptions to let pipelines
            # fail independently without aborting the entire batch
            results = await asyncio.gather(
                *pipeline_tasks, return_exceptions=True
            )

            # Aggregate pipeline results into workflow state
            self._aggregate_pipeline_results(results, pipeline_configs)

            self._state.current_phase = "exploitation"
            self._state.current_agent = None

            await self._log_phase(
                activity_input,
                "vulnerability-exploitation",
                "complete",
                retry,
            )

            # Final findings aggregation after all pipelines complete
            await workflow.execute_activity(
                "aggregate_findings",
                args=[activity_input],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            # ===============================================================
            # Phase 5b: Chain Exploitation
            # ===============================================================
            if stages.run_chain:
                await self._run_chain_exploitation(activity_input, retry)
            else:
                workflow.logger.info("Chain exploitation skipped (stage disabled)")

            # ===============================================================
            # Phase 5c: Findings Critique
            # ===============================================================
            # Re-aggregate findings immediately before remediation to ensure
            # the index includes chain findings and any late evidence updates
            await workflow.execute_activity(
                "aggregate_findings",
                args=[activity_input],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            # Critic agent annotates the aggregated findings index with
            # confidence verdicts, preconditions, severity adjustments, and
            # conditional-on flags. Output: deliverables/findings_critique.json.
            # Both remediation and the report read this sidecar to apply
            # corrections without mutating the original findings index.
            await self._run_sequential_phase(
                "critique", "report-critic", activity_input, retry
            )

            # Deterministic recall guard: reconcile the index against the
            # critique (every finding must be annotated) and enforce the
            # severity/reachability floor on include_in_report. Writes
            # findings_critique_audit.json and logs loudly; non-fatal so a
            # transient issue never blocks delivery, but silent TP drops become
            # visible and traceable.
            try:
                await workflow.execute_activity(
                    "audit_critique",
                    args=[activity_input],
                    start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                    retry_policy=retry,
                )
            except Exception as exc:
                workflow.logger.warning("Critique audit failed (non-fatal): %s", exc)

            # ===============================================================
            # Phase 6: Remediation
            # ===============================================================
            if stages.run_remediation:
                # Rebuild git from upstream so fix branches have correct ancestry
                # for direct push. Non-fatal: remediation still runs if this fails.
                # Capture the outcome so "no upstream (code-only)" is distinguishable
                # from a genuine rebuild failure, and neither is silently hidden.
                rebuild_ok = False
                try:
                    rebuild_ok = bool(await workflow.execute_activity(
                        "rebuild_git",
                        args=[activity_input],
                        start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                        retry_policy=retry,
                    ))
                    workflow.logger.info(
                        "Git rebuild %s — fix branches will %s be pushable upstream",
                        "succeeded" if rebuild_ok else "did not establish an upstream",
                        "" if rebuild_ok else "not",
                    )
                except Exception as exc:
                    workflow.logger.warning("Git rebuild failed (non-fatal): %s", exc)

                await self._run_remediation_phase(activity_input, retry)

                # Post-remediation: export fix branches as .patch files (standalone artifacts)
                try:
                    patch_result = await workflow.execute_activity(
                        "export_patches",
                        args=[activity_input],
                        start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                        retry_policy=retry,
                    )
                    if patch_result.get("exported"):
                        workflow.logger.info(
                            "Exported %d patches to deliverables/patches/",
                            len(patch_result["exported"]),
                        )
                except Exception as exc:
                    workflow.logger.warning("Patch export failed (non-fatal): %s", exc)

                # Verify each fix branch by re-running the finding's confirmation
                # harness against the patched code (exit 0 = still vulnerable,
                # non-zero = fixed). Writes verified=pass|fail|not_tested into the
                # manifest; the report badges "verified" only on pass. Non-fatal.
                try:
                    verify_result = await workflow.execute_activity(
                        "verify_patches",
                        args=[activity_input],
                        # Larger budget: re-runs a harness per fix branch. Results are
                        # persisted per-branch, so a timeout still keeps prior work.
                        start_to_close_timeout=_REPORT_START_TO_CLOSE,
                        retry_policy=retry,
                    )
                    workflow.logger.info("Patch verification: %s", verify_result)
                except Exception as exc:
                    workflow.logger.warning("Patch verification failed (non-fatal): %s", exc)
            else:
                workflow.logger.info("Remediation skipped (stage disabled)")

            # Note: push + MR creation are handled by the remediation agent
            # directly (sub-agents push branches, orchestrator creates MRs).
            # The push_fix_branches and create_merge_request activities are
            # kept in activities.py as fallback but not called here.

            # ===============================================================
            # Phase 7: Reporting
            # ===============================================================
            self._state.current_phase = "reporting"
            self._state.current_agent = "report"

            await self._log_phase(
                activity_input, "reporting", "start", retry
            )

            # Assemble concatenated report from evidence + remediation files
            await workflow.execute_activity(
                "assemble_report",
                args=[activity_input],
                start_to_close_timeout=_REPORT_START_TO_CLOSE,
                retry_policy=retry,
            )

            # Run report agent to add executive summary. The report author's
            # single source of truth is deliverables/findings_critique.json (the
            # critic's structured adjudication) — it derives counts, grouping,
            # and possible-false-positive flags from that directly.
            report_metrics = await workflow.execute_activity(
                "run_agent",
                args=["report", activity_input],
                activity_id="run_agent:report",
                start_to_close_timeout=_AGENT_START_TO_CLOSE,
                heartbeat_timeout=_AGENT_HEARTBEAT,
                retry_policy=retry,
            )
            self._state.agent_metrics["report"] = report_metrics
            self._state.completed_agents.append("report")

            # Inject model metadata into final report
            await workflow.execute_activity(
                "inject_report_metadata",
                args=[activity_input],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            await self._log_phase(
                activity_input, "reporting", "complete", retry
            )

            # ===============================================================
            # Pipeline complete
            # ===============================================================
            self._state.status = "completed"
            self._state.current_phase = None
            self._state.current_agent = None
            self._state.summary = self._compute_summary()

            await workflow.execute_activity(
                "log_workflow_complete",
                args=[
                    activity_input,
                    self._build_workflow_summary("completed"),
                ],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            return self._state.model_dump()

        except Exception as e:
            self._state.status = "failed"
            self._state.failed_agent = self._state.current_agent
            # Unwrap Temporal's wrappers to the real ApplicationError reason (type +
            # message) instead of the generic "Activity task failed", so the run's
            # error + the workflow.log banner tell the user what actually went wrong.
            try:
                from temporalio.exceptions import ApplicationError as _AppErr
                _cur, _msg = e, None
                for _ in range(12):
                    if _cur is None:
                        break
                    _m = getattr(_cur, "message", None)
                    if isinstance(_cur, _AppErr) and _m:
                        _t = getattr(_cur, "type", None)
                        _msg = f"{_t}: {_m}" if _t else _m
                        break
                    _cur = getattr(_cur, "cause", None)
                self._state.error = (_msg or str(e))[:2000]
            except Exception:
                self._state.error = str(e)[:2000]
            self._state.summary = self._compute_summary()

            try:
                await workflow.execute_activity(
                    "log_workflow_complete",
                    args=[
                        activity_input,
                        self._build_workflow_summary("failed"),
                    ],
                    start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                    retry_policy=retry,
                )
            except Exception:
                workflow.logger.warn(
                    "Failed to log workflow completion on error"
                )

            raise

    # -------------------------------------------------------------------
    # Resume skip check
    # -------------------------------------------------------------------

    def _should_skip(self, agent_name: str) -> bool:
        """Return True if the agent was already completed in a previous run."""
        return agent_name in self._completed_from_resume

    # -------------------------------------------------------------------
    # Sequential phase helper
    # -------------------------------------------------------------------

    async def _run_sequential_phase(
        self,
        phase: str,
        agent_name: str,
        input: ActivityInput,
        retry: RetryPolicy,
    ) -> None:
        """Run a single-agent sequential phase (pre-recon, recon, remediation)."""
        self._state.current_phase = phase
        self._state.current_agent = agent_name

        if self._should_skip(agent_name):
            workflow.logger.info("Skipping %s (already complete)", agent_name)
            self._state.completed_agents.append(agent_name)
            return

        await self._log_phase(input, phase, "start", retry)

        metrics = await workflow.execute_activity(
            "run_agent",
            args=[agent_name, input],
            activity_id=f"run_agent:{agent_name}",
            start_to_close_timeout=_AGENT_START_TO_CLOSE,
            heartbeat_timeout=_AGENT_HEARTBEAT,
            retry_policy=retry,
        )

        self._state.agent_metrics[agent_name] = metrics
        self._state.completed_agents.append(agent_name)

        await self._log_phase(input, phase, "complete", retry)

    # -------------------------------------------------------------------
    # Vuln+exploit pipeline (per vuln type)
    # -------------------------------------------------------------------

    async def _run_vuln_exploit_pipeline(
        self,
        vuln_type: str,
        input: ActivityInput,
        retry: RetryPolicy,
    ) -> dict[str, Any]:
        """Run a single vuln->exploit pipeline for one vulnerability type.

        Steps:
        1. Run vuln agent
        2. Check exploitation queue
        3. Aggregate findings (for cross-type awareness)
        4. Run exploit agent (if queue has findings)
        5. Check needs_more_info (feedback loop, max 1)
        """
        vuln_agent = f"{vuln_type}-vuln"
        exploit_agent = f"{vuln_type}-exploit"
        has_exploit = vuln_type not in _NO_EXPLOIT_TYPES

        # 1. Run vulnerability analysis agent
        vuln_metrics: dict[str, Any] | None = None
        if self._should_skip(vuln_agent):
            workflow.logger.info("Skipping %s (already complete)", vuln_agent)
            self._state.completed_agents.append(vuln_agent)
        else:
            vuln_metrics = await workflow.execute_activity(
                "run_agent",
                args=[vuln_agent, input],
                activity_id=f"run_agent:{vuln_agent}",
                start_to_close_timeout=_AGENT_START_TO_CLOSE,
                heartbeat_timeout=_AGENT_HEARTBEAT,
                retry_policy=retry,
            )
            self._state.agent_metrics[vuln_agent] = vuln_metrics
            self._state.completed_agents.append(vuln_agent)

        if not has_exploit:
            return _vuln_exploit_result(
                vuln_type, vuln_metrics=vuln_metrics
            )

        # 2. Check exploitation queue for actionable findings
        decision = await workflow.execute_activity(
            "check_exploitation_queue",
            args=[input, vuln_type],
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=retry,
        )

        if not decision.get("should_exploit", False):
            workflow.logger.info(
                "No exploitable findings for %s, skipping exploit agent",
                vuln_type,
            )
            return _vuln_exploit_result(
                vuln_type,
                vuln_metrics=vuln_metrics,
                exploit_decision=decision,
            )

        # 3. Aggregate findings between vuln and exploit phases
        await workflow.execute_activity(
            "aggregate_findings",
            args=[input],
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=retry,
        )

        # 4. Run exploitation agent
        exploit_metrics: dict[str, Any] | None = None
        if self._should_skip(exploit_agent):
            workflow.logger.info("Skipping %s (already complete)", exploit_agent)
            self._state.completed_agents.append(exploit_agent)
            return _vuln_exploit_result(
                vuln_type,
                vuln_metrics=vuln_metrics,
                exploit_decision=decision,
            )

        exploit_metrics = await workflow.execute_activity(
            "run_agent",
            args=[exploit_agent, input],
            activity_id=f"run_agent:{exploit_agent}",
            start_to_close_timeout=_AGENT_START_TO_CLOSE,
            heartbeat_timeout=_AGENT_HEARTBEAT,
            retry_policy=retry,
        )
        self._state.agent_metrics[exploit_agent] = exploit_metrics
        self._state.completed_agents.append(exploit_agent)

        # 5. Feedback loop: check if exploit agent needs more info
        needs_info = await workflow.execute_activity(
            "check_needs_more_info",
            args=[input, vuln_type],
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=retry,
        )

        if needs_info and not self._feedback_used.get(vuln_type, False):
            self._feedback_used[vuln_type] = True
            workflow.logger.info(
                "Feedback loop triggered for %s: %d questions",
                vuln_type,
                len(needs_info.get("questions", [])),
            )

            # Clean up the needs_more_info file to prevent re-triggering on resume
            await workflow.execute_activity(
                "cleanup_needs_more_info",
                args=[input, vuln_type],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            # Back up the existing exploitation queue before vuln re-run
            # (the re-run will overwrite the queue — we merge after)
            await workflow.execute_activity(
                "backup_exploitation_queue",
                args=[input, vuln_type],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            # Build extra context from exploit agent's questions
            questions = needs_info.get("questions", [])
            context_needed = needs_info.get("context_needed", "")
            extra = "The exploit agent requested additional analysis:\n\n"
            extra += "\n".join(f"- {q}" for q in questions)
            if context_needed:
                extra += f"\n\nContext: {context_needed}"

            feedback_input = dataclasses.replace(input, extra_context=extra)

            # Re-run vuln agent with exploit questions injected into prompt
            re_vuln_metrics = await workflow.execute_activity(
                "run_agent",
                args=[vuln_agent, feedback_input],
                activity_id=f"run_agent:{vuln_agent}:feedback",
                start_to_close_timeout=_AGENT_START_TO_CLOSE,
                heartbeat_timeout=_AGENT_HEARTBEAT,
                retry_policy=retry,
            )
            # Update metrics with the feedback-loop run
            self._state.agent_metrics[vuln_agent] = re_vuln_metrics

            # Merge the backup queue with the new queue to prevent data loss
            await workflow.execute_activity(
                "merge_exploitation_queue_backup",
                args=[input, vuln_type],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            # Re-aggregate findings after vuln re-run
            await workflow.execute_activity(
                "aggregate_findings",
                args=[input],
                start_to_close_timeout=_UTILITY_START_TO_CLOSE,
                retry_policy=retry,
            )

            # Re-run exploit agent
            re_exploit_metrics = await workflow.execute_activity(
                "run_agent",
                args=[exploit_agent, input],
                activity_id=f"run_agent:{exploit_agent}:feedback",
                start_to_close_timeout=_AGENT_START_TO_CLOSE,
                heartbeat_timeout=_AGENT_HEARTBEAT,
                retry_policy=retry,
            )
            self._state.agent_metrics[exploit_agent] = re_exploit_metrics
            exploit_metrics = re_exploit_metrics

        return _vuln_exploit_result(
            vuln_type,
            vuln_metrics=vuln_metrics,
            exploit_metrics=exploit_metrics,
            exploit_decision=decision,
        )

    # -------------------------------------------------------------------
    # Phase 5b: Chain exploitation
    # -------------------------------------------------------------------

    async def _run_chain_exploitation(
        self,
        input: ActivityInput,
        retry: RetryPolicy,
    ) -> None:
        """Phase 5b: attempt to chain findings across vulnerability types.

        Only runs if at least 2 vuln types produced confirmed findings.
        """
        self._state.current_phase = "chain-exploitation"
        self._state.current_agent = "chain-exploit"

        if self._should_skip("chain-exploit"):
            workflow.logger.info("Skipping chain-exploit (already complete)")
            self._state.completed_agents.append("chain-exploit")
            return

        # Gate: check if chaining is worth attempting
        decision = await workflow.execute_activity(
            "check_chain_exploit_readiness",
            args=[input],
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=retry,
        )

        if not decision["should_chain"]:
            workflow.logger.info(
                "Skipping chain exploitation: only %d types with findings (need >= 2)",
                decision["types_with_findings"],
            )
            return

        await self._log_phase(input, "chain-exploitation", "start", retry)

        metrics = await workflow.execute_activity(
            "run_agent",
            args=["chain-exploit", input],
            activity_id="run_agent:chain-exploit",
            start_to_close_timeout=_AGENT_START_TO_CLOSE,
            heartbeat_timeout=_AGENT_HEARTBEAT,
            retry_policy=retry,
        )
        self._state.agent_metrics["chain-exploit"] = metrics
        self._state.completed_agents.append("chain-exploit")

        # Re-aggregate findings to include chain findings
        await workflow.execute_activity(
            "aggregate_findings",
            args=[input],
            start_to_close_timeout=_UTILITY_START_TO_CLOSE,
            retry_policy=retry,
        )

        await self._log_phase(input, "chain-exploitation", "complete", retry)

    # -------------------------------------------------------------------
    # Phase 6: Remediation (longer timeout for orchestrator)
    # -------------------------------------------------------------------

    async def _run_remediation_phase(
        self,
        input: ActivityInput,
        retry: RetryPolicy,
    ) -> None:
        """Phase 6: remediation with extended timeout.

        The remediation agent is an orchestrator that spawns sub-agents for
        parallel patching — it needs more time than standard agents.
        """
        self._state.current_phase = "remediation"
        self._state.current_agent = "remediation"

        if self._should_skip("remediation"):
            workflow.logger.info("Skipping remediation (already complete)")
            self._state.completed_agents.append("remediation")
            return

        await self._log_phase(input, "remediation", "start", retry)

        metrics = await workflow.execute_activity(
            "run_agent",
            args=["remediation", input],
            activity_id="run_agent:remediation",
            start_to_close_timeout=_REMEDIATION_START_TO_CLOSE,
            heartbeat_timeout=_AGENT_HEARTBEAT,
            retry_policy=retry,
        )

        self._state.agent_metrics["remediation"] = metrics
        self._state.completed_agents.append("remediation")

        await self._log_phase(input, "remediation", "complete", retry)

    # -------------------------------------------------------------------
    # Pipeline configuration builder
    # -------------------------------------------------------------------

    def _build_pipeline_configs(
        self, detected_tech: dict[str, Any]
    ) -> list[dict[str, str]]:
        """Build the list of vuln+exploit pipeline configs.

        Always-run types are included unconditionally. GraphQL and WebSocket
        are included only if detected by the pre-recon agent.
        """
        configs: list[dict[str, str]] = []

        # Always-run types
        for vt in _ALWAYS_RUN_TYPES:
            configs.append({"vuln_type": vt})

        # Conditional: GraphQL
        if detected_tech.get("graphql", False):
            configs.append({"vuln_type": "graphql"})

        # Conditional: WebSocket
        if detected_tech.get("websocket", False):
            configs.append({"vuln_type": "websocket"})

        workflow.logger.info(
            "Pipeline configs: %s",
            [c["vuln_type"] for c in configs],
        )
        return configs

    # -------------------------------------------------------------------
    # Pipeline result aggregation
    # -------------------------------------------------------------------

    def _aggregate_pipeline_results(
        self,
        results: list[dict[str, Any] | BaseException],
        configs: list[dict[str, str]],
    ) -> None:
        """Aggregate settled pipeline results into workflow state.

        Successful pipelines have their metrics recorded. Failed pipelines
        are logged as warnings but do not abort the entire workflow.
        """
        failed_pipelines: list[str] = []

        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                vuln_type = (
                    configs[i]["vuln_type"] if i < len(configs) else "unknown"
                )
                error_msg = str(result)[:500]
                failed_pipelines.append(f"{vuln_type}: {error_msg}")
                workflow.logger.warn(
                    "Pipeline %s failed: %s", vuln_type, error_msg
                )
                continue

            # Result is a dict from _vuln_exploit_result
            if isinstance(result, dict):
                vuln_type = result.get("vuln_type", "unknown")
                vuln_agent = f"{vuln_type}-vuln"
                exploit_agent = f"{vuln_type}-exploit"

                # Metrics are already recorded by _run_vuln_exploit_pipeline
                # via self._state mutations. This is just for logging.
                if result.get("vuln_metrics"):
                    workflow.logger.info(
                        "Pipeline %s: vuln completed", vuln_type
                    )
                if result.get("exploit_metrics"):
                    workflow.logger.info(
                        "Pipeline %s: exploit completed", vuln_type
                    )

        if failed_pipelines:
            workflow.logger.warn(
                "%d pipeline(s) failed: %s",
                len(failed_pipelines),
                "; ".join(failed_pipelines),
            )

    # -------------------------------------------------------------------
    # Summary computation
    # -------------------------------------------------------------------

    def _compute_summary(self) -> PipelineSummary:
        """Compute aggregated metrics from all completed agents."""
        total_cost = 0.0
        total_turns = 0
        agent_count = len(self._state.completed_agents)

        for metrics in self._state.agent_metrics.values():
            # Handle both dict (from activity return) and AgentMetrics
            if isinstance(metrics, dict):
                total_cost += metrics.get("cost_usd") or 0.0
                total_turns += metrics.get("num_turns") or 0
            elif isinstance(metrics, AgentMetrics):
                total_cost += metrics.cost_usd or 0.0
                total_turns += metrics.num_turns or 0

        elapsed_ms = int(
            (workflow.now().timestamp() - self._state.start_time) * 1000
        )

        return PipelineSummary(
            total_cost_usd=total_cost,
            total_duration_ms=elapsed_ms,
            total_turns=total_turns,
            agent_count=agent_count,
        )

    def _build_workflow_summary(
        self, status: str
    ) -> dict[str, Any]:
        """Build a workflow summary dict for the log_workflow_complete activity."""
        summary = self._compute_summary()
        return {
            "status": status,
            "total_cost_usd": summary.total_cost_usd,
            "total_duration_ms": summary.total_duration_ms,
            "total_turns": summary.total_turns,
            "agent_count": summary.agent_count,
            "completed_agents": list(self._state.completed_agents),
            "failed_agent": self._state.failed_agent,
            "error": self._state.error,
            "agent_metrics": {
                k: v if isinstance(v, dict) else v.model_dump()
                for k, v in self._state.agent_metrics.items()
            },
        }

    # -------------------------------------------------------------------
    # Phase logging helper
    # -------------------------------------------------------------------

    async def _log_phase(
        self,
        input: ActivityInput,
        phase: str,
        event: str,
        retry: RetryPolicy,
    ) -> None:
        """Log a phase transition via the log_phase_transition activity."""
        await workflow.execute_activity(
            "log_phase_transition",
            args=[input, phase, event],
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=retry,
        )
