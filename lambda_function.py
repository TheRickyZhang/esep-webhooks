from typing import Any, Dict, Mapping, TypedDict, cast
import os, json, hmac, hashlib, base64, urllib.request

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
SLACK_URL = os.environ.get("SLACK_URL", "")           # course-provided URL
ALLOW_UNVERIFIED = os.environ.get("ALLOW_UNVERIFIED", "false").lower() == "true"

class LambdaEvent(TypedDict, total=False):
    headers: Mapping[str, str]
    body: str
    isBase64Encoded: bool

def _verify(headers: Mapping[str,str], raw: bytes) -> bool:
    sig = headers.get("X-Hub-Signature-256") or headers.get("x-hub-signature-256")
    if not sig:
        return ALLOW_UNVERIFIED
    mac = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest("sha256="+mac, sig)

def _slack(text: str) -> None:
    if not SLACK_URL: return
    data = json.dumps({"text": text}).encode()
    req = urllib.request.Request(SLACK_URL, data=data, headers={"Content-Type":"application/json"})
    try: urllib.request.urlopen(req, timeout=5)
    except Exception as e: print("slack error:", e)

def lambda_handler(event: LambdaEvent, _ctx: Any) -> Dict[str, Any]:
    raw = base64.b64decode(event["body"]) if event.get("isBase64Encoded") else event["body"].encode()
    headers = cast(Mapping[str,str], event.get("headers", {}))
    if not _verify(headers, raw):
        return {"statusCode": 401, "body": "invalid signature"}

    payload: Dict[str, Any] = json.loads(raw.decode("utf-8"))
    hdrs = {k.lower(): v for k,v in headers.items()}
    gh_event = hdrs.get("x-github-event", "unknown")

    if gh_event == "issues" and payload.get("action") in ("opened","reopened"):
        repo = payload.get("repository",{}).get("full_name","")
        issue = cast(Dict[str, Any], payload.get("issue") or {})
        url = issue.get("html_url") or issue.get("url")
        if not url and payload.get("repository",{}).get("html_url") and issue.get("number"):
            url = f"{payload['repository']['html_url']}/issues/{issue['number']}"
        title = issue.get("title","(no title)")
        _slack(f"Issue {payload.get('action')} in {repo}: {title}\n{url or 'URL not found'}")

    return {"statusCode": 200, "body": "ok"}

