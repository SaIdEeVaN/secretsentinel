"""Registered local repositories (explicit allowlisted folders only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import Settings
from ..core.errors import ErrorCode, SecretSentinelError
from ..core.security import canonicalize_existing_dir, ensure_within_allowed_roots, safe_text
from ..models import Repository, Scan
from ..schemas import DemoCreated, RepositoryCreate, RepositoryOut
from ..services.store import audit, get_or_create_repository
from .deps import get_db, get_or_404, get_settings, repository_out

router = APIRouter(tags=["repositories"])


@router.get("/repositories", response_model=list[RepositoryOut])
def list_repositories(session: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    repos = session.scalars(select(Repository).order_by(Repository.display_name)).all()
    return [repository_out(session, r, settings) for r in repos]


@router.post("/repositories", response_model=RepositoryOut, status_code=status.HTTP_201_CREATED)
def register_repository(
    body: RepositoryCreate, session: Session = Depends(get_db), settings: Settings = Depends(get_settings)
):
    target = canonicalize_existing_dir(body.path)
    ensure_within_allowed_roots(target, settings.scan_root_allowlist)
    repo = get_or_create_repository(session, target, body.display_name)
    if body.display_name:
        repo.display_name = safe_text(body.display_name, 200)
    session.flush()
    return repository_out(session, repo, settings)


@router.get("/repositories/{repository_id}", response_model=RepositoryOut)
def get_repository(repository_id: str, session: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    return repository_out(session, get_or_404(session, Repository, repository_id), settings)


@router.delete("/repositories/{repository_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_repository(repository_id: str, session: Session = Depends(get_db)):
    repo = get_or_404(session, Repository, repository_id)
    active = session.scalar(
        select(Scan.id).where(Scan.repository_id == repo.id, Scan.status.in_(("queued", "running"))).limit(1)
    )
    if active:
        raise SecretSentinelError(ErrorCode.SCAN_ALREADY_RUNNING)
    audit(session, "local-user", "repository.deleted", "repository", repo.id)
    session.delete(repo)
    return None


@router.post("/demo", response_model=DemoCreated, status_code=status.HTTP_201_CREATED)
def create_demo(session: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    """Create a synthetic demo repository inside the first allowed scan root."""
    from ..services.demo import create_demo_repo

    if not settings.scan_root_allowlist:
        raise SecretSentinelError(ErrorCode.PATH_NOT_ALLOWED, "Configure SCAN_ROOT_ALLOWLIST first.")
    root = settings.scan_root_allowlist[0]
    root.mkdir(parents=True, exist_ok=True)
    name, n = "secretsentinel-demo", 1
    while (root / name).exists():
        n += 1
        name = f"secretsentinel-demo-{n}"
        if n > 50:
            raise SecretSentinelError(ErrorCode.INVALID_STATE)
    path = create_demo_repo(root / name, settings.git_path)
    target = canonicalize_existing_dir(path)
    ensure_within_allowed_roots(target, settings.scan_root_allowlist)
    repo = get_or_create_repository(session, target, f"Demo ({name})")
    session.flush()
    return DemoCreated(repository=repository_out(session, repo, settings))
