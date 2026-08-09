
from fastapi import APIRouter, HTTPException, Request
from src.integrations.ticketing import get_all_tickets

router = APIRouter()

@router.get("/tickets", tags=["Tickets"])
async def list_tickets(request: Request):
    """List all created incident tickets."""
    try:
        tickets = get_all_tickets()
        return {"tickets": tickets}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
