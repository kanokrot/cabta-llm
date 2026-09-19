
from fastapi import APIRouter, Depends, HTTPException
from src.integrations.ticketing import get_all_tickets
from ..auth import TEAM_LEAD, get_current_user

router = APIRouter()


def ticket_owner_scope(current_user: dict):
    """Return the ticket query owner, or None for intentionally unscoped roles."""
    if current_user.get("role") in {"admin", TEAM_LEAD}:
        return None
    return current_user["id"]


@router.get("/tickets", tags=["Tickets"])
async def list_tickets(
    current_user: dict = Depends(get_current_user),
):
    """List tickets visible to the authenticated user."""
    try:
        tickets = get_all_tickets(owner_id=ticket_owner_scope(current_user))
        return {"tickets": tickets}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
