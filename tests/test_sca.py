"""Tests for SCA (Software Composition Analysis) pipeline integration.

Covers agent registration, deliverable types, report stats integration,
prompt existence, and findings aggregation for supply chain findings.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------


class TestSCAAgentRegistration:
    """SCA agent must be registered in all pipeline registries."""

    def test_agent_name_type_includes_sca(self):
        from src.types.agents import AgentName
        assert "sca" in AgentName.__args__

    def test_all_agents_includes_sca(self):
        from src.types.agents import ALL_AGENTS
        assert "sca" in ALL_AGENTS

    def test_phase_name_includes_sca(self):
        from src.types.agents import PhaseName
        assert "sca" in PhaseName.__args__

    def test_agents_registry_has_sca(self):
        from src.session_manager import AGENTS
        assert "sca" in AGENTS
        sca = AGENTS["sca"]
        assert sca.name == "sca"
        assert sca.prompt_template == "sca"
        assert sca.deliverable_filename == "sca_findings.json"
        assert sca.model_tier == "medium"
        assert sca.conditional is False

    def test_agent_phase_map_has_sca(self):
        from src.session_manager import AGENT_PHASE_MAP
        assert "sca" in AGENT_PHASE_MAP
        assert AGENT_PHASE_MAP["sca"] == "sca"

    def test_playwright_session_mapping_has_sca(self):
        from src.session_manager import PLAYWRIGHT_SESSION_MAPPING
        assert "sca" in PLAYWRIGHT_SESSION_MAPPING


# ---------------------------------------------------------------------------
# Deliverable type registration
# ---------------------------------------------------------------------------


class TestSCADeliverableType:
    """SCA_FINDINGS must be a recognized deliverable type."""

    def test_deliverable_type_includes_sca(self):
        from src.types.deliverables import DeliverableType
        assert "SCA_FINDINGS" in DeliverableType.__args__

    def test_deliverable_filename_mapping(self):
        from src.types.deliverables import DELIVERABLE_FILENAMES
        assert "SCA_FINDINGS" in DELIVERABLE_FILENAMES
        assert DELIVERABLE_FILENAMES["SCA_FINDINGS"] == "sca_findings.json"

    def test_save_deliverable_script_has_sca(self):
        script_path = Path(__file__).resolve().parent.parent / "scripts" / "save_deliverable.py"
        source = script_path.read_text()
        assert '"SCA_FINDINGS"' in source
        assert '"sca_findings.json"' in source


# ---------------------------------------------------------------------------
# Prompt file
# ---------------------------------------------------------------------------


class TestSCAPrompt:
    """SCA prompt file must exist and contain expected content."""

    def test_prompt_file_exists(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "sca.txt"
        assert prompt_path.is_file(), f"Missing prompt file: {prompt_path}"

    def test_prompt_includes_shared_tools(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "sca.txt"
        content = prompt_path.read_text()
        assert "@include(shared/_tools.txt)" in content

    def test_prompt_has_repo_path_variable(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "sca.txt"
        content = prompt_path.read_text()
        assert "{{REPO_PATH}}" in content

    def test_prompt_references_web_search(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "sca.txt"
        content = prompt_path.read_text()
        assert "WebSearch" in content

    def test_prompt_references_save_deliverable(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "sca.txt"
        content = prompt_path.read_text()
        assert "SCA_FINDINGS" in content

    def test_prompt_specifies_json_output_format(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "sca.txt"
        content = prompt_path.read_text()
        assert "SCA-VULN-" in content
        assert '"vulnerabilities"' in content


# ---------------------------------------------------------------------------
# Report prompt — supply chain section
# ---------------------------------------------------------------------------


class TestReportPromptSupplyChain:
    """Report prompt must include supply chain in its rendering instructions."""

    def test_report_prompt_lists_sca_category(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "report-executive.txt"
        content = prompt_path.read_text()
        assert "Supply Chain (SCA)" in content

    def test_report_prompt_lists_sca_findings_input(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "report-executive.txt"
        content = prompt_path.read_text()
        assert "sca_findings.json" in content

    def test_report_prompt_has_sca_section(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "report-executive.txt"
        content = prompt_path.read_text()
        assert "Supply Chain (SCA) Section" in content


# ---------------------------------------------------------------------------
# Findings aggregator — SCA integration
# ---------------------------------------------------------------------------


class TestFindingsAggregatorSCA:
    """findings_aggregator must merge sca_findings.json into the index."""

    @pytest.mark.asyncio
    async def test_aggregator_reads_sca_findings(self, tmp_path):
        deliverables = tmp_path / "deliverables"
        deliverables.mkdir()

        sca_data = {
            "manifests_scanned": 2,
            "packages_scanned": 50,
            "vulnerabilities": [
                {
                    "ID": "SCA-VULN-001",
                    "package": "lodash",
                    "version": "4.17.15",
                    "ecosystem": "npm",
                    "vulnerability_type": "Supply_Chain",
                    "cve_ids": ["CVE-2021-23337"],
                    "severity": "high",
                    "title": "Prototype Pollution",
                    "description": "Command injection via template.",
                    "fixed_version": "4.17.21",
                    "code_fixable": False,
                    "status": "unconfirmed",
                },
            ],
        }
        (deliverables / "sca_findings.json").write_text(json.dumps(sca_data))

        from src.services.findings_aggregator import FindingsAggregator

        result = await FindingsAggregator().aggregate(str(tmp_path))

        assert result["total_vulnerabilities"] >= 1
        assert "supply_chain" in result["by_type"]
        assert len(result["by_type"]["supply_chain"]) == 1
        assert result["by_type"]["supply_chain"][0]["ID"] == "SCA-VULN-001"

    @pytest.mark.asyncio
    async def test_aggregator_handles_missing_sca_file(self, tmp_path):
        deliverables = tmp_path / "deliverables"
        deliverables.mkdir()

        from src.services.findings_aggregator import FindingsAggregator

        result = await FindingsAggregator().aggregate(str(tmp_path))
        assert "supply_chain" not in result.get("by_type", {})

    @pytest.mark.asyncio
    async def test_aggregator_handles_empty_sca_vulnerabilities(self, tmp_path):
        deliverables = tmp_path / "deliverables"
        deliverables.mkdir()

        sca_data = {
            "manifests_scanned": 1,
            "packages_scanned": 10,
            "vulnerabilities": [],
        }
        (deliverables / "sca_findings.json").write_text(json.dumps(sca_data))

        from src.services.findings_aggregator import FindingsAggregator

        result = await FindingsAggregator().aggregate(str(tmp_path))
        assert "supply_chain" not in result.get("by_type", {})


# ---------------------------------------------------------------------------
# Workflow — no stale run_sca_scan references
# ---------------------------------------------------------------------------


class TestNoStaleReferences:
    """Verify old run_sca_scan activity was removed cleanly."""

    def test_activities_has_no_run_sca_scan(self):
        activities_path = Path(__file__).resolve().parent.parent / "src" / "temporal" / "activities.py"
        source = activities_path.read_text()
        assert "run_sca_scan" not in source

    def test_worker_has_no_run_sca_scan(self):
        worker_path = Path(__file__).resolve().parent.parent / "src" / "temporal" / "worker.py"
        source = worker_path.read_text()
        assert "run_sca_scan" not in source

    def test_no_sca_scanner_service(self):
        scanner_path = Path(__file__).resolve().parent.parent / "src" / "services" / "sca_scanner.py"
        assert not scanner_path.exists(), "sca_scanner.py should be deleted — SCA is now an agent"


# ---------------------------------------------------------------------------
# report_stats.py removed — critic's adjudication is the single source of truth
# ---------------------------------------------------------------------------


class TestReportStatsRemoved:
    """report_stats.py (deterministic counts + regex remediation scraping) is
    gone; the report author consumes findings_critique.json directly."""

    _SRC = Path(__file__).resolve().parent.parent / "src"

    def test_module_deleted(self):
        assert not (self._SRC / "services" / "report_stats.py").exists()

    def test_no_source_imports_report_stats(self):
        """The deleted ``report_stats.py`` module must not be imported anywhere.
        (Reading a legacy ``report_stats.json`` deliverable for back-compat — e.g.
        the webapi metrics extractor / demo engine — is fine and not a violation.)"""
        import re
        mod_import = re.compile(
            r"(from\s+[\w.]*\breport_stats\b\s+import|"
            r"import\s+[\w.]*\breport_stats\b|"
            r"services[./]report_stats)"
        )
        offenders = []
        for py in self._SRC.rglob("*.py"):
            if "greybox" in py.parts:
                continue
            if mod_import.search(py.read_text()):
                offenders.append(str(py.relative_to(self._SRC)))
        assert not offenders, f"stale report_stats module imports: {offenders}"

    def test_no_compute_report_stats_activity(self):
        worker = (self._SRC / "temporal" / "worker.py").read_text()
        workflows = (self._SRC / "temporal" / "workflows.py").read_text()
        assert "compute_report_stats" not in worker
        assert "compute_report_stats" not in workflows
