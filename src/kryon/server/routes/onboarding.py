"""Customer onboarding wizard API routes."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from kryon.server.auth import require_api_key
from kryon.server.auth.deps import get_current_user
from kryon.server.auth.isolation import require_resource_access, verify_client_access
from kryon.server.auth.models import User
from kryon.server.deps import get_store
from kryon.server.exceptions import not_found
from kryon.server.logging_config import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["onboarding"], dependencies=[Depends(require_api_key)])


class StartBody(BaseModel):
    client_name: str = Field(..., min_length=1, max_length=200)
    contact: str = Field("", max_length=500)


class StepBody(BaseModel):
    step: int = Field(..., ge=1, le=5)
    data: dict = {}


class CredentialBody(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=100)
    credential_type: str = Field(..., min_length=1, max_length=100)
    label: str = Field("", max_length=200)
    data: dict = {}


class ImportBody(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=100)
    format: str = Field("json", pattern=r"^(json|csv)$")
    data: str = Field("", max_length=10_000_000)


class ValidateScopeBody(BaseModel):
    targets: list[str] = Field([], max_length=100)


@router.post("/onboarding/start")
async def start_onboarding(body: StartBody) -> dict:
    """Start a new onboarding session."""
    store = get_store()
    session_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    # Create client
    from kryon.memory.models import Client

    client_id = str(uuid.uuid4())
    client = Client(id=client_id, name=body.client_name, contact=body.contact, created_at=now)
    store.create_client(client)

    # Create onboarding session
    store.save_onboarding_session(session_id=session_id, client_id=client_id, started_at=now)

    logger.info("Onboarding started: session=%s client=%s", session_id, client_id)
    return {"session_id": session_id, "client_id": client_id}


@router.put("/onboarding/{session_id}/step")
async def update_step(session_id: str, body: StepBody) -> dict:
    """Update onboarding session step."""
    store = get_store()
    session = store.get_onboarding_session(session_id)
    if not session:
        logger.warning("Onboarding session not found: %s", session_id)
        raise not_found("OnboardingSession", session_id)

    # Merge step data
    existing_data = json.loads(session.get("data_json", "{}"))
    existing_data[f"step_{body.step}"] = body.data
    store.update_onboarding_session(
        session_id,
        current_step=body.step,
        data_json=json.dumps(existing_data),
    )
    logger.info("Onboarding step updated: session=%s step=%d", session_id, body.step)
    return {"session_id": session_id, "current_step": body.step}


@router.get("/onboarding/{session_id}")
async def get_session(session_id: str) -> dict:
    """Get onboarding session state."""
    store = get_store()
    session = store.get_onboarding_session(session_id)
    if not session:
        logger.warning("Onboarding session not found: %s", session_id)
        raise not_found("OnboardingSession", session_id)
    return session


@router.post("/onboarding/{session_id}/complete")
async def complete_onboarding(session_id: str) -> dict:
    """Finalize onboarding — mark complete."""
    store = get_store()
    session = store.get_onboarding_session(session_id)
    if not session:
        raise not_found("OnboardingSession", session_id)

    now = datetime.now(timezone.utc).isoformat()
    store.update_onboarding_session(session_id, completed_at=now)

    logger.info("Onboarding completed: session=%s client=%s", session_id, session["client_id"])
    return {"session_id": session_id, "completed": True, "client_id": session["client_id"]}


@router.post("/onboarding/credentials")
async def save_credential(body: CredentialBody, user: User | None = Depends(get_current_user)) -> dict:
    """Save an encrypted credential."""
    # client_id is operator-supplied → verify the caller may write to that client (BOLA guard).
    verify_client_access(user, body.client_id, get_store())
    encryption_key = os.environ.get("KRYON_CREDENTIAL_KEY", "")
    if not encryption_key:
        raise HTTPException(status_code=500, detail="Server configuration error")

    from kryon.onboarding.vault import CredentialVault

    vault = CredentialVault(encryption_key)
    encrypted = vault.encrypt_credential(body.data)

    store = get_store()
    cred_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    store.save_credential(
        cred_id=cred_id,
        client_id=body.client_id,
        credential_type=body.credential_type,
        label=body.label,
        encrypted_data=encrypted,
        created_at=now,
    )
    # nosemgrep: python-logger-credential-disclosure
    logger.info(
        "Credential saved: id=%s client=%s type=%s", cred_id, body.client_id, body.credential_type
    )  # nosemgrep: python-logger-credential-disclosure
    return {"id": cred_id, "client_id": body.client_id}


@router.get("/onboarding/credentials/{client_id}")
async def list_credentials(client_id: str, user: User | None = Depends(get_current_user)) -> list[dict]:
    """List credentials (metadata only, no decryption)."""
    store = get_store()
    require_resource_access(user, client_id, store, kind="Credential", resource_id=client_id)
    return store.list_credentials(client_id)


@router.delete("/onboarding/credentials/{cred_id}")
async def delete_credential(cred_id: str, user: User | None = Depends(get_current_user)) -> dict:
    """Delete a credential."""
    store = get_store()
    # Resolve the credential's owning client and guard before deleting (BOLA — a foreign
    # cred_id is indistinguishable from a missing one).
    cred = store.get_credential(cred_id)
    if cred is None:
        raise not_found("Credential", cred_id)
    require_resource_access(user, cred["client_id"], store, kind="Credential", resource_id=cred_id)
    if not store.delete_credential(cred_id):
        logger.warning("Credential not found for delete: %s", cred_id)  # nosemgrep: python-logger-credential-disclosure
        raise not_found("Credential", cred_id)
    logger.info("Credential deleted: %s", cred_id)  # nosemgrep: python-logger-credential-disclosure
    return {"deleted": True, "id": cred_id}


@router.post("/onboarding/import-assets")
async def import_assets(body: ImportBody) -> dict:
    """Import assets from CSV or JSON."""
    store = get_store()
    if body.format == "csv":
        from kryon.onboarding.importer import import_assets_csv

        count = import_assets_csv(body.data, body.client_id, store)
    else:
        from kryon.onboarding.importer import import_assets_json

        count = import_assets_json(body.data, body.client_id, store)
    logger.info("Assets imported: count=%d client=%s format=%s", count, body.client_id, body.format)
    return {"imported": count, "client_id": body.client_id}


@router.post("/onboarding/validate-scope")
async def validate_scope_endpoint(body: ValidateScopeBody) -> dict:
    """Validate scope target reachability."""
    from kryon.onboarding.importer import validate_scope

    results = validate_scope(body.targets)
    logger.info("Scope validated: %d targets, %d reachable", len(results), sum(1 for r in results if r["reachable"]))
    return {"results": results, "total": len(results), "reachable": sum(1 for r in results if r["reachable"])}
