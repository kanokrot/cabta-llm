"""Shared Team Lead oversight enforcement helpers."""

from fastapi import HTTPException, Request


def record_cross_user_read(
    request: Request,
    actor_user_id: int,
    actor_role: str,
    target_user_id: int,
    resource_type: str,
    resource_id: str,
) -> str:
    """Persist a cross-user read before returning the protected data."""
    agent_store = getattr(request.app.state, "agent_store", None)
    if agent_store is None or not hasattr(agent_store, "add_cross_user_read_audit"):
        raise HTTPException(
            status_code=503,
            detail="Audit logging is unavailable",
        )
    return agent_store.add_cross_user_read_audit(
        actor_user_id=actor_user_id,
        actor_role=actor_role,
        target_user_id=target_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
    )
