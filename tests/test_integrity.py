"""Tests for code integrity analysis pipeline integration.

Covers agent registration, deliverable types, report stats integration,
prompt existence, report prompt integration, and findings aggregation
for integrity (malicious code detection) findings.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Agent registration
# ---------------------------------------------------------------------------


class TestIntegrityAgentRegistration:
    """Integrity agent must be registered in all pipeline registries."""

    def test_agent_name_type_includes_integrity(self):
        from src.types.agents import AgentName
        assert "integrity" in AgentName.__args__

    def test_all_agents_includes_integrity(self):
        from src.types.agents import ALL_AGENTS
        assert "integrity" in ALL_AGENTS

    def test_phase_name_includes_integrity(self):
        from src.types.agents import PhaseName
        assert "integrity" in PhaseName.__args__

    def test_agents_registry_has_integrity(self):
        from src.session_manager import AGENTS
        assert "integrity" in AGENTS
        agent = AGENTS["integrity"]
        assert agent.name == "integrity"
        assert agent.prompt_template == "integrity"
        assert agent.deliverable_filename == "integrity_analysis.json"
        assert agent.model_tier == "large"
        assert agent.conditional is False

    def test_agent_phase_map_has_integrity(self):
        from src.session_manager import AGENT_PHASE_MAP
        assert "integrity" in AGENT_PHASE_MAP
        assert AGENT_PHASE_MAP["integrity"] == "integrity"

    def test_playwright_session_mapping_has_integrity(self):
        from src.session_manager import PLAYWRIGHT_SESSION_MAPPING
        assert "integrity" in PLAYWRIGHT_SESSION_MAPPING


# ---------------------------------------------------------------------------
# Deliverable type registration
# ---------------------------------------------------------------------------


class TestIntegrityDeliverableType:
    """INTEGRITY_ANALYSIS must be a recognized deliverable type."""

    def test_deliverable_type_includes_integrity(self):
        from src.types.deliverables import DeliverableType
        assert "INTEGRITY_ANALYSIS" in DeliverableType.__args__

    def test_deliverable_filename_mapping(self):
        from src.types.deliverables import DELIVERABLE_FILENAMES
        assert "INTEGRITY_ANALYSIS" in DELIVERABLE_FILENAMES
        assert DELIVERABLE_FILENAMES["INTEGRITY_ANALYSIS"] == "integrity_analysis.json"

    def test_save_deliverable_script_has_integrity(self):
        script_path = Path(__file__).resolve().parent.parent / "scripts" / "save_deliverable.py"
        source = script_path.read_text()
        assert '"INTEGRITY_ANALYSIS"' in source
        assert '"integrity_analysis.json"' in source


# ---------------------------------------------------------------------------
# Prompt file
# ---------------------------------------------------------------------------


class TestIntegrityPrompt:
    """Integrity prompt file must exist and contain expected content."""

    def test_prompt_file_exists(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "integrity.txt"
        assert prompt_path.is_file(), f"Missing prompt file: {prompt_path}"

    def test_prompt_includes_shared_tools(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "integrity.txt"
        content = prompt_path.read_text()
        assert "@include(shared/_tools.txt)" in content

    def test_prompt_has_repo_path_variable(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "integrity.txt"
        content = prompt_path.read_text()
        assert "{{REPO_PATH}}" in content

    def test_prompt_references_save_deliverable(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "integrity.txt"
        content = prompt_path.read_text()
        assert "INTEGRITY_ANALYSIS" in content

    def test_prompt_specifies_json_output_format(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "integrity.txt"
        content = prompt_path.read_text()
        assert "INTEGRITY-" in content
        assert '"findings"' in content

    def test_prompt_defines_confidence_levels(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "integrity.txt"
        content = prompt_path.read_text()
        assert "confidence" in content
        assert "high" in content
        assert "medium" in content

    def test_prompt_defines_all_categories(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "integrity.txt"
        content = prompt_path.read_text()
        for category in ("exfiltration", "backdoor", "obfuscation",
                         "credential_harvesting", "suspicious_binary",
                         "supply_chain_tampering"):
            assert category in content, f"Prompt missing category: {category}"


# ---------------------------------------------------------------------------
# Report prompt — integrity section
# ---------------------------------------------------------------------------


class TestReportPromptIntegrity:
    """Report prompt must include integrity in its rendering instructions."""

    def test_report_prompt_lists_integrity_category(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "report-executive.txt"
        content = prompt_path.read_text()
        assert "Code Integrity" in content

    def test_report_prompt_lists_integrity_findings_input(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "report-executive.txt"
        content = prompt_path.read_text()
        assert "integrity_analysis.json" in content

    def test_report_prompt_has_integrity_section(self):
        prompt_path = Path(__file__).resolve().parent.parent / "prompts" / "report-executive.txt"
        content = prompt_path.read_text()
        assert "Code Integrity Section" in content


# ---------------------------------------------------------------------------
# Findings aggregator — integrity integration
# ---------------------------------------------------------------------------


class TestFindingsAggregatorIntegrity:
    """findings_aggregator must merge integrity_analysis.json into the index."""

    @pytest.mark.asyncio
    async def test_aggregator_reads_integrity_findings(self, tmp_path):
        deliverables = tmp_path / "deliverables"
        deliverables.mkdir()

        integrity_data = {
            "files_scanned": 245,
            "issues_found": 1,
            "findings": [
                {
                    "id": "INTEGRITY-001",
                    "severity": "critical",
                    "confidence": "high",
                    "category": "backdoor",
                    "title": "Hidden admin endpoint",
                    "file_path": "src/routes/debug.py",
                    "line_numbers": [42, 58],
                    "description": "Undocumented route with hardcoded auth bypass.",
                    "evidence": "subprocess.run(cmd, shell=True)",
                    "legitimate_explanation": None,
                    "code_fixable": True,
                },
            ],
        }
        (deliverables / "integrity_analysis.json").write_text(json.dumps(integrity_data))

        from src.services.findings_aggregator import FindingsAggregator

        result = await FindingsAggregator().aggregate(str(tmp_path))

        assert result["total_vulnerabilities"] >= 1
        assert "integrity" in result["by_type"]
        assert len(result["by_type"]["integrity"]) == 1
        assert result["by_type"]["integrity"][0]["id"] == "INTEGRITY-001"

    @pytest.mark.asyncio
    async def test_aggregator_handles_missing_integrity_file(self, tmp_path):
        deliverables = tmp_path / "deliverables"
        deliverables.mkdir()

        from src.services.findings_aggregator import FindingsAggregator

        result = await FindingsAggregator().aggregate(str(tmp_path))
        assert "integrity" not in result.get("by_type", {})

    @pytest.mark.asyncio
    async def test_aggregator_handles_empty_integrity_findings(self, tmp_path):
        deliverables = tmp_path / "deliverables"
        deliverables.mkdir()

        integrity_data = {
            "files_scanned": 100,
            "issues_found": 0,
            "findings": [],
        }
        (deliverables / "integrity_analysis.json").write_text(json.dumps(integrity_data))

        from src.services.findings_aggregator import FindingsAggregator

        result = await FindingsAggregator().aggregate(str(tmp_path))
        assert "integrity" not in result.get("by_type", {})


# ---------------------------------------------------------------------------
# No stale references
# ---------------------------------------------------------------------------


class TestNoStaleReferences:
    """Verify no old integrity-related artifacts exist."""

    def test_no_integrity_scanner_service(self):
        scanner_path = Path(__file__).resolve().parent.parent / "src" / "services" / "integrity_scanner.py"
        assert not scanner_path.exists(), "integrity_scanner.py should not exist — integrity is an agent"
