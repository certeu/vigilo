"""Configuration type definitions for pipeline input and YAML config.

Maps to Shannon's Config/PipelineInput TypeScript types, extended with
resume support, terminated workflow tracking.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class Rule(BaseModel):
    """A scope rule that tells agents what to avoid or focus on."""

    description: str
    type: str = "path"
    url_path: str = ""


class SuccessCondition(BaseModel):
    """Condition to verify successful authentication."""

    type: str
    value: str


class Credentials(BaseModel):
    """Login credentials for authenticated testing."""

    username: str
    password: str
    totp_secret: str | None = None


class Authentication(BaseModel):
    """Full authentication configuration for the target application."""

    login_type: Literal["form", "sso", "cookie"] = "form"
    login_url: str = ""
    credentials: Credentials | None = None
    login_flow: list[str] = Field(default_factory=list)
    success_condition: SuccessCondition | None = None
    cookie_header: str | None = None

    @model_validator(mode="after")
    def _validate_cookie_auth(self) -> Authentication:
        if self.login_type == "cookie":
            if not self.cookie_header or not self.cookie_header.strip():
                raise ValueError(
                    "cookie_header is required when login_type is 'cookie'"
                )
        elif self.login_type in ("form", "sso"):
            if self.credentials is None:
                raise ValueError(
                    f"credentials are required when login_type is '{self.login_type}'"
                )
        return self


class PipelineConfig(BaseModel):
    """Runtime pipeline configuration options."""

    retry_preset: str | None = None
    max_concurrent_pipelines: int = 8


class PipelineInput(BaseModel):
    """Top-level input to the PentestPipelineWorkflow.

    Passed from the CLI / worker to Temporal when starting a workflow execution.
    """

    web_url: str = ""
    repo_path: str
    config_path: str | None = None
    output_path: str | None = None
    pipeline_config: PipelineConfig | None = None
    workflow_id: str | None = None
    session_id: str | None = None
    resume_from_workspace: str | None = None
    terminated_workflows: list[str] = Field(default_factory=list)
    description: str = ""
    # Optional stage selection (preset name or flag-dict). None → full pipeline
    # (legacy behavior). See src/types/stages.py. Exploitation is always welded to
    # vuln and critique always runs — these cannot be disabled here.
    stages: dict[str, Any] | str | None = None
