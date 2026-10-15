"""Website inspection and robustness-report endpoints."""
import json
import logging
import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .analyzer import site_inspect

ROBUSTNESS = Path(__file__).resolve().parent / "model" / "robustness.json"
RATE_LIMIT = 10
RATE_WINDOW = 60

log = logging.getLogger("fraudlens")
router = APIRouter()
_hits: dict[str, deque] = defaultdict(deque)


class InspectRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2000, description="Web address to inspect")


def _limited(request: Request) -> bool:
    ip = request.client.host if request.client else "unknown"
    now, q = time.monotonic(), _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


@router.post("/api/inspect-site")
def inspect_site(body: InspectRequest, request: Request):
    """Download only the HTML of a page (nothing runs, nothing is stored) and look for fake-login signs."""
    if _limited(request):
        raise HTTPException(status_code=429, detail="Too many website inspections. Please wait a minute.")
    url = body.url.strip()
    if any(c.isspace() for c in url):
        raise HTTPException(status_code=422, detail="Enter a single web address.")
    try:
        result = site_inspect.inspect(url)
    except Exception:
        log.exception("site inspection failed")
        raise HTTPException(status_code=500, detail="Website inspection failed. Please try again.")
    log.info("inspected site level=%s score=%s ms=%.1f", result["level"], result["score"], result["elapsed_ms"])
    return result


@router.get("/api/robustness")
def robustness():
    if not ROBUSTNESS.exists():
        raise HTTPException(status_code=404, detail="Robustness report not generated yet. Run scripts/stress_test.py.")
    return JSONResponse(json.loads(ROBUSTNESS.read_text(encoding="utf-8")))
