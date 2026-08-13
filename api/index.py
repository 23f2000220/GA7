import re
from typing import Literal, Optional, Union

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, ValidationError

app = FastAPI()

# ---- Assigned scope ---------------------------------------------------
TENANT_ID = "tenant-9solhek"
EMAIL_DOMAIN = "notify-3jc6d8n.example"

ALLOWED_TOOLS = {"search", "lookup_record", "send_email", "render_html"}


# ---- Top-level request shape -------------------------------------------
class ActionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str
    args: dict


class FirewallRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provenance: Literal["trusted", "untrusted"]
    humanApproved: bool
    untrustedContent: Optional[str] = None
    action: ActionModel


# ---- Per-tool argument schemas ------------------------------------------
class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=200)


class LookupRecordArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenantId: str = Field(min_length=1)
    recordId: str = Field(min_length=1)


class SendEmailArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: str = Field(min_length=1)
    subject: str
    body: str


class RenderHtmlArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    html: str


TOOL_ARG_MODELS = {
    "search": SearchArgs,
    "lookup_record": LookupRecordArgs,
    "send_email": SendEmailArgs,
    "render_html": RenderHtmlArgs,
}

# ---- HTML safety (structural, not phrase-matching) ----------------------
_SCRIPT_RE = re.compile(r"<\s*script\b", re.IGNORECASE)
_IFRAME_RE = re.compile(r"<\s*iframe\b", re.IGNORECASE)
_ON_ATTR_RE = re.compile(r"\bon[a-z]+\s*=", re.IGNORECASE)
_JS_URL_RE = re.compile(r"javascript\s*:", re.IGNORECASE)


def is_unsafe_html(html: str) -> bool:
    return bool(
        _SCRIPT_RE.search(html)
        or _IFRAME_RE.search(html)
        or _ON_ATTR_RE.search(html)
        or _JS_URL_RE.search(html)
    )


# ---- Response shape -------------------------------------------------
class FirewallResponse(BaseModel):
    decision: Literal["allow", "block"]
    reason: str


def allow() -> FirewallResponse:
    return FirewallResponse(decision="allow", reason="ALLOW")


def block(reason: str) -> FirewallResponse:
    return FirewallResponse(decision="block", reason=reason)


@app.post("/q2/action-firewall", response_model=FirewallResponse)
def action_firewall(payload: dict):
    # 1. Top-level schema
    try:
        req = FirewallRequest.model_validate(payload)
    except ValidationError:
        return block("INVALID_SCHEMA")

    tool = req.action.tool

    # 2. Tool allowlist
    if tool not in ALLOWED_TOOLS:
        return block("TOOL_NOT_ALLOWED")

    # 3. Selected tool's argument schema
    arg_model = TOOL_ARG_MODELS[tool]
    try:
        args = arg_model.model_validate(req.action.args)
    except ValidationError:
        return block("INVALID_SCHEMA")

    # 4. Tenant scope (lookup_record only)
    if tool == "lookup_record":
        if args.tenantId != TENANT_ID:
            return block("TENANT_SCOPE")

    # 5-6. Egress domain + approval (send_email only)
    if tool == "send_email":
        domain = args.to.rsplit("@", 1)[-1] if "@" in args.to else ""
        if domain != EMAIL_DOMAIN:
            return block("EGRESS_DENIED")
        if not req.humanApproved:
            return block("APPROVAL_REQUIRED")

    # 7. HTML safety (render_html only)
    if tool == "render_html":
        if is_unsafe_html(args.html):
            return block("UNSAFE_OUTPUT")

    # No rule failed
    return allow()

##################################
# ---- q3 -----------------------
##################################
import re
from typing import Literal, Optional

class TFState(BaseModel):
    model_config = ConfigDict(strict=True)
    backend: str
    locked: bool

class TFResource(BaseModel):
    model_config = ConfigDict(strict=True)
    address: str
    type: str
    action: Literal["create", "update", "delete"]
    labels: dict
    secret: Optional[str] = None
    forceDestroy: bool

class TerraformPlanRequest(BaseModel):
    model_config = ConfigDict(strict=True)
    environment: str
    state: TFState
    providerVersion: str
    destroyApproved: bool
    resource: TFResource


# ---- OUTPUT shape (what you send back) ----

class TerraformPlanResponse(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str


# ---- constants for your assigned scope ----

PROD_WORKSPACE = "prod-l722ec"
REQUIRED_LABELS = {
    "owner": "student-6sp9e",
    "environment": "production",
    "cost_center": "cc-5sj8",
}
VALID_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
PROTECTED_DELETE_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}

EXACT_VERSION_RE = re.compile(r"^=?\s*\d+\.\d+\.\d+$")
PESSIMISTIC_VERSION_RE = re.compile(r"^~>\s*\d+(\.\d+){1,2}$")


def is_pinned_version(v: str) -> bool:
    v = v.strip()
    if v.lower() == "latest":
        return False
    if ">=" in v or "*" in v:
        return False
    return bool(EXACT_VERSION_RE.match(v) or PESSIMISTIC_VERSION_RE.match(v))


@app.post("/q3/terraform/plan", response_model=TerraformPlanResponse)
def terraform_plan(body: dict):
    # Rule 1: schema/type validation
    try:
        plan = TerraformPlanRequest(**body)
    except ValidationError:
        return TerraformPlanResponse(decision="reject", reason="INVALID_PLAN")

    # Rule 2: environment must match assigned workspace
    if plan.environment != PROD_WORKSPACE:
        return TerraformPlanResponse(decision="reject", reason="ENVIRONMENT_MISMATCH")

    # Rule 3: state must use an allowed backend AND be locked
    if plan.state.backend not in VALID_BACKENDS or not plan.state.locked:
        return TerraformPlanResponse(decision="reject", reason="STATE_UNSAFE")

    # Rule 4: provider version must be pinned (exact or pessimistic)
    if not is_pinned_version(plan.providerVersion):
        return TerraformPlanResponse(decision="reject", reason="UNPINNED_PROVIDER")

    # Rule 5: all three required labels must be present with exact values
    for key, value in REQUIRED_LABELS.items():
        if plan.resource.labels.get(key) != value:
            return TerraformPlanResponse(decision="reject", reason="MISSING_LABELS")

    # Rule 6: secret must be null or a non-empty secret://... reference
    secret = plan.resource.secret
    if secret is not None:
        if not secret.startswith("secret://") or secret == "secret://":
            return TerraformPlanResponse(decision="reject", reason="PLAINTEXT_SECRET")

    # Rule 7: deleting a protected resource type requires explicit approval
    if plan.resource.action == "delete" and plan.resource.type in PROTECTED_DELETE_TYPES:
        if not plan.destroyApproved:
            return TerraformPlanResponse(decision="reject", reason="DELETE_NOT_APPROVED")

    # Rule 8: a production storage_bucket may never use forceDestroy: true
    if plan.resource.type == "storage_bucket" and plan.resource.forceDestroy:
        return TerraformPlanResponse(decision="reject", reason="FORCE_DESTROY")

    # All rules passed
    return TerraformPlanResponse(decision="approve", reason="APPROVE")