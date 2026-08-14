
import urllib.parse
import html
import re
from typing import Literal, Optional, Union
from fastapi import FastAPI,Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError



app = FastAPI()


##################################
# ---- q2 -----------------------
##################################
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



##################################
# ---- q4 -----------------------
##################################


ALLOWED_HOSTS = {"cdn-dcl8mta.example", "app-mcawlsi.example"}
VALID_CHANNELS = {"html", "markdown", "url", "sql", "shell"}
MAX_LEN = 20000


def multi_step_decode(input_string):
    # Step 1: Percent-decode
    step1 = urllib.parse.unquote(input_string)
    # Step 2: HTML-entity-decode (named, numeric, hex)
    step2 = html.unescape(step1)
    # Step 3: \uXXXX unicode escape decode
    try:
        step3 = re.sub(
            r'\\u([0-9a-fA-F]{4})',
            lambda m: chr(int(m.group(1), 16)),
            step2
        )
    except Exception:
        step3 = step2
    return step3


SCRIPT_TAG_RE = re.compile(r'<\s*(script|iframe|object|embed)\b', re.IGNORECASE)
EVENT_HANDLER_RE = re.compile(r'\bon[a-zA-Z]+\s*=', re.IGNORECASE)
DANGEROUS_SCHEME_TEXT_RE = re.compile(r'\b(javascript|data|vbscript)\s*:', re.IGNORECASE)

HTML_ATTR_URL_RE = re.compile(r'(?:src|href)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
MARKDOWN_URL_RE = re.compile(r'\]\(([^)]*)\)')

SQL_METACHAR_RE = re.compile(r"""('|"|;|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b)""", re.IGNORECASE)
SHELL_METACHAR_RE = re.compile(r'[;&|`<>]|\$\(|\$\{')


def extract_urls(channel, text):
    if channel == "html":
        print("TESTING HMTL", HTML_ATTR_URL_RE.findall(text))
        return HTML_ATTR_URL_RE.findall(text)
    if channel == "markdown":
        print("TESTING MARKDOWN", MARKDOWN_URL_RE.findall(text))
        return MARKDOWN_URL_RE.findall(text)
    if channel == "url":
        print("TESTING URL", text.strip())
        return [text.strip()]
    return []


def get_hostname(raw_url):
    """Returns (scheme, hostname) for an absolute reference, or (None, None)
    for a relative one. Protocol-relative //host counts as absolute https."""
    u = raw_url.strip()
    if not u:
        return None, None
    parsed = urllib.parse.urlsplit(u)
    if not parsed.netloc:
        return None, None  # relative reference like /local/page -> fine
    scheme = parsed.scheme.lower() if parsed.scheme else "https"  # //host -> https
    print("RETURNED SCHEME/HOSTNAME",scheme, parsed.hostname )
    return scheme, parsed.hostname  # .hostname strips credentials + port for us


def check_scheme_and_exfil(channel, text):
    if DANGEROUS_SCHEME_TEXT_RE.search(text):
        print("DANGEREOUS_SCHEME",DANGEROUS_SCHEME_TEXT_RE.search(text))
        return "DANGEROUS_SCHEME"
    for raw_url in extract_urls(channel, text):
        scheme, hostname = get_hostname(raw_url)
        if hostname is None:
            continue
        if scheme not in ("http", "https"):
            print("SCHEME NOT IN http/https - DANGEROUS_SCHEME",scheme)
            return "DANGEROUS_SCHEME"
        if hostname not in ALLOWED_HOSTS:
            print("HOST NAME NOT IN ALLOWED HOSTS - EXTERNAL_EXFIL",hostname)
            return "EXTERNAL_EXFIL"
    return None


def check_channel_rules(channel, text):
    if channel == "html":
        if SCRIPT_TAG_RE.search(text):
            print("TESTING SCRIPT_TAG_RE",SCRIPT_TAG_RE.search(text))
            return "SCRIPT_TAG"
        if EVENT_HANDLER_RE.search(text):
            print("TESTING EVENT_HANDLER_RE",EVENT_HANDLER_RE.search(text))
            return "EVENT_HANDLER"
        return check_scheme_and_exfil(channel, text)
    if channel in ("markdown", "url"):
        return check_scheme_and_exfil(channel, text)
    if channel == "sql":
        return "SQL_METACHAR" if SQL_METACHAR_RE.search(text) else None
    if channel == "shell":
        return "SHELL_METACHAR" if SHELL_METACHAR_RE.search(text) else None
    return None


@app.post("/q4/sanitize-output")
async def sanitize_output(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"safe": False, "reason": "INVALID_SCHEMA"})

    if not isinstance(body, dict):
        return JSONResponse({"safe": False, "reason": "INVALID_SCHEMA"})

    channel = body.get("channel")
    output = body.get("output")

    if channel not in VALID_CHANNELS or not isinstance(output, str) or len(output) > MAX_LEN:
        return JSONResponse({"safe": False, "reason": "INVALID_SCHEMA"})

    decoded = multi_step_decode(output)
    if decoded != output and check_channel_rules(channel, decoded) is not None:
        return JSONResponse({"safe": False, "reason": "ENCODED_PAYLOAD"})

    reason = check_channel_rules(channel, output)
    if reason is None:
        return JSONResponse({"safe": True, "reason": "SAFE"})
    return JSONResponse({"safe": False, "reason": reason})