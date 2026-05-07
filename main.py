import os
import logging
import hashlib
import hmac
import httpx

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from typing import Optional
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# CONFIGURATION (via environment variables)
# ============================================================
JIRA_BASE_URL      = os.getenv("JIRA_BASE_URL")           # https://yourcompany.atlassian.net
JIRA_USER_EMAIL    = os.getenv("JIRA_USER_EMAIL")          # service account email
JIRA_API_TOKEN     = os.getenv("JIRA_API_TOKEN")           # token generated at Atlassian
JIRA_PROJECT_KEY   = os.getenv("JIRA_PROJECT_KEY")         # e.g. "SEC"
JIRA_ISSUE_TYPE_ID = os.getenv("JIRA_ISSUE_TYPE_ID")       # Jira issue type ID
WEBHOOK_SECRET     = os.getenv("VISIONONE_WEBHOOK_SECRET") # shared secret with VisionOne
VISIONONE_API_BASE = os.getenv("VISIONONE_API_BASE", "https://api.xdr.trendmicro.com")
VISIONONE_TOKEN    = os.getenv("VISIONONE_TOKEN")

# Custom field IDs — set these via environment variables to match your Jira instance
JIRA_FIELD_CREATED_AT = os.getenv("JIRA_FIELD_CREATED_AT")  # e.g. "customfield_XXXXX"
JIRA_FIELD_HOST_NAME  = os.getenv("JIRA_FIELD_HOST_NAME")   # e.g. "customfield_XXXXX"
JIRA_FIELD_ALERT_ID   = os.getenv("JIRA_FIELD_ALERT_ID")    # e.g. "customfield_XXXXX"

# ============================================================
# LOGGING
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="VisionOne → Jira Webhook Receiver")

# ============================================================
# MAPPINGS
# ============================================================
SEVERITY_TO_PRIORITY = {
    "critical": "1",
    "high":     "2",
    "medium":   "3",
    "low":      "4",
}

SEVERITY_TO_LABEL = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
}

SUPPORTED_ENTITY_TYPES = {"host", "account", "emailaddress", "url"}

# ============================================================
# SECURITY — validate VisionOne HMAC signature
# ============================================================
def verify_signature(raw_body: bytes, signature_header: Optional[str]) -> bool:
    """
    VisionOne sends X-TrendMicro-Signature with HMAC-SHA256 of the body.
    Validates the request is legitimate.
    """
    if not WEBHOOK_SECRET:
        logger.warning("VISIONONE_WEBHOOK_SECRET not configured — skipping signature validation.")
        return True

    if not signature_header:
        logger.error("X-TrendMicro-Signature header missing from request.")
        return False

    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature_header)

# ============================================================
# JIRA — check if an issue already exists for a given alertId
# ============================================================
async def alert_issue_exists(client: httpx.AsyncClient, alert_id: str) -> bool:
    jql = f'"Alert ID[Short text]" = "{alert_id}" AND project = "{JIRA_PROJECT_KEY}"'
    response = await client.get(
        f"{JIRA_BASE_URL}/rest/api/3/search",
        params={"jql": jql, "maxResults": 1, "fields": "id"},
    )
    if response.status_code == 200:
        return response.json().get("total", 0) > 0
    logger.warning(f"[Jira] Failed to check duplicate for alert {alert_id}. Status: {response.status_code}")
    return False

# ============================================================
# JIRA — build ADF payload and create the issue
# ============================================================
def build_adf_list_item(key: str, value: str) -> dict:
    return {
        "type": "listItem",
        "content": [{
            "type": "paragraph",
            "content": [
                {"type": "text", "text": f"{key}: ", "marks": [{"type": "strong"}]},
                {"type": "text", "text": value or "N/A"},
            ]
        }]
    }

def build_issue_payload(entity: dict) -> dict:
    severity    = (entity.get("severity") or "low").lower()
    priority    = SEVERITY_TO_PRIORITY.get(severity, "4")
    label       = SEVERITY_TO_LABEL.get(severity, "LOW")
    entity_type = entity.get("entity_type", "host").upper()
    host_name   = entity.get("host_name", "unknown")
    rules_text  = ", ".join(r.get("name", "") for r in (entity.get("matched_rules") or [])) or "N/A"
    ips_text    = entity.get("ips") or "N/A"

    payload = {
        "fields": {
            "project":   {"key": JIRA_PROJECT_KEY},
            "issuetype": {"id": JIRA_ISSUE_TYPE_ID},
            "priority":  {"id": priority},
            "summary":   f"[{label}] Alert {entity_type}: {host_name}",
            "labels":    ["VisionOne", "Security", label, entity_type],
            "description": {
                "version": 1,
                "type": "doc",
                "content": [
                    {
                        "type": "heading",
                        "attrs": {"level": 3},
                        "content": [{"type": "text", "text": "Alert Description"}]
                    },
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": entity.get("description") or "No description provided."}]
                    },
                    {
                        "type": "heading",
                        "attrs": {"level": 3},
                        "content": [{"type": "text", "text": "Technical Details"}]
                    },
                    {
                        "type": "bulletList",
                        "content": [
                            build_adf_list_item("Severity",      severity.capitalize()),
                            build_adf_list_item("Entity Type",   entity_type),
                            build_adf_list_item("Detected IPs",  ips_text),
                            build_adf_list_item("Matched Rules", rules_text),
                            build_adf_list_item("Alert ID",      entity.get("alert_id") or "N/A"),
                            build_adf_list_item("Created at",    entity.get("created_at") or "N/A"),
                        ]
                    }
                ]
            },
        }
    }

    # Populate custom fields only if env vars are set
    if JIRA_FIELD_CREATED_AT:
        payload["fields"][JIRA_FIELD_CREATED_AT] = entity.get("created_at")
    if JIRA_FIELD_HOST_NAME:
        payload["fields"][JIRA_FIELD_HOST_NAME] = host_name
    if JIRA_FIELD_ALERT_ID:
        payload["fields"][JIRA_FIELD_ALERT_ID] = entity.get("alert_id")

    return payload

async def create_jira_issue(client: httpx.AsyncClient, entity: dict) -> dict:
    payload  = build_issue_payload(entity)
    response = await client.post(
        f"{JIRA_BASE_URL}/rest/api/3/issue",
        json=payload,
    )
    return {"status": response.status_code, "body": response.json()}

# ============================================================
# VISIONONE — fetch full alert details by ID
# (webhook may deliver a summarized payload)
# ============================================================
async def fetch_full_alert(client: httpx.AsyncClient, alert_id: str) -> Optional[dict]:
    response = await client.get(
        f"{VISIONONE_API_BASE}/v3.0/workbench/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {VISIONONE_TOKEN}"}
    )
    if response.status_code == 200:
        return response.json()
    logger.error(f"[VisionOne] Failed to fetch alert {alert_id}. Status: {response.status_code}")
    return None

# ============================================================
# ENTITY EXTRACTION
# ============================================================
def extract_entities(alert: dict) -> list:
    entities = []
    for entity in (alert.get("impactScope") or {}).get("entities") or []:
        entity_type = (entity.get("entityType") or "").lower()
        if entity_type not in SUPPORTED_ENTITY_TYPES:
            continue

        entity_value = entity.get("entityValue") or {}
        host_name = entity_value.get("name") if isinstance(entity_value, dict) else str(entity_value)

        entities.append({
            "alert_id":      alert.get("id"),
            "severity":      alert.get("severity"),
            "created_at":    alert.get("createdDateTime"),
            "description":   alert.get("description"),
            "matched_rules": alert.get("matchedRules"),
            "entity_type":   entity_type,
            "host_name":     host_name,
            "ips":           ", ".join(entity.get("ips") or []),
        })
    return entities

# ============================================================
# MAIN ALERT PROCESSING
# ============================================================
async def process_alert(alert: dict) -> dict:
    result = {"created": [], "skipped": [], "failed": []}

    auth    = (JIRA_USER_EMAIL, JIRA_API_TOKEN)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    async with httpx.AsyncClient(auth=auth, headers=headers, timeout=15.0) as client:
        entities = extract_entities(alert)

        if not entities:
            logger.warning(f"[Alert {alert.get('id')}] No supported entities found.")
            return result

        for entity in entities:
            alert_id  = entity["alert_id"]
            host_name = entity["host_name"]

            # Check for duplicate in Jira
            if await alert_issue_exists(client, alert_id):
                logger.info(f"[Skipped] Issue already exists for alert {alert_id} — {host_name}")
                result["skipped"].append({"alert_id": alert_id, "entity": host_name})
                continue

            # Create issue
            response = await create_jira_issue(client, entity)
            if response["status"] == 201:
                issue_key = response["body"].get("key", "N/A")
                logger.info(f"[Created] Issue {issue_key} — alert {alert_id} [{entity['severity'].upper()}] — {host_name}")
                result["created"].append({"alert_id": alert_id, "entity": host_name, "issue_key": issue_key})
            else:
                logger.error(f"[Failed] Could not create issue — alert {alert_id} — {host_name} — Status: {response['status']} — {response['body']}")
                result["failed"].append({"alert_id": alert_id, "entity": host_name, "error": response["body"]})

    return result

# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/webhook/visionone")
async def receive_webhook(
    request: Request,
    x_trendmicro_signature: Optional[str] = Header(None)
):
    """
    Receives VisionOne alerts in real time via webhook.

    Configure in VisionOne:
      URL:    https://<your-app>.onrender.com/webhook/visionone
      Body:   {"type":"$type$","data":"$payload$"}
      Header: {"X-TrendMicro-Signature": "<hmac-of-body>"}
    """
    raw_body = await request.body()

    # 1. Validate HMAC signature
    if not verify_signature(raw_body, x_trendmicro_signature):
        raise HTTPException(status_code=401, detail="Invalid signature.")

    # 2. Parse payload
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload.")

    alert_data = payload.get("data") or payload
    alert_id   = alert_data.get("id") or alert_data.get("alertId")

    logger.info(f"[Webhook] Alert received: {alert_id} | Type: {payload.get('type')}")

    # 3. If payload is summarized (ID only), fetch full details from VisionOne
    if alert_id and not alert_data.get("impactScope"):
        logger.info(f"[Webhook] Summarized payload detected. Fetching full details for alert {alert_id}...")
        async with httpx.AsyncClient(timeout=10.0) as client:
            alert_data = await fetch_full_alert(client, alert_id) or alert_data

    # 4. Process alert and create Jira issues
    result = await process_alert(alert_data)

    return JSONResponse(content={"ok": True, "result": result})
