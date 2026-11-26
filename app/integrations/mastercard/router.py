"""Admin-gated sandbox endpoints. No secrets are returned by these routes."""
import os
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel
from app.integrations.mastercard.client import MastercardClient, MastercardConfigError
from app.financial_context.normalizer import normalize_accounts
router=APIRouter(prefix="/integrations/mastercard",tags=["Mastercard Open Finance sandbox"])
def client():
    if os.getenv("MASTERCARD_ENABLED","false").lower() not in ("1","true","yes"):
        raise HTTPException(503,"Mastercard integration disabled")
    try: return MastercardClient()
    except MastercardConfigError as e: raise HTTPException(503,str(e))
def admin(key):
    expected=os.getenv("PAARI_ADMIN_API_KEY","")
    if not expected or not key or key!=expected: raise HTTPException(401,"Admin authentication required")
class Customer(BaseModel):
    username:str; first_name:str; last_name:str
class Connect(BaseModel):
    customer_id:str; redirect_uri:str|None=None
class Transactions(BaseModel):
    customer_id:str; account_id:str; from_date:int; to_date:int
@router.get("/status")
def status():
    return {"enabled":os.getenv("MASTERCARD_ENABLED","false").lower() in ("1","true","yes"),"credentials_configured":all(os.getenv(x) for x in ("MASTERCARD_PARTNER_ID","MASTERCARD_PARTNER_SECRET","MASTERCARD_APP_KEY")),"mode":os.getenv("MASTERCARD_ENV","sandbox")}
@router.post("/customers/testing")
def create_customer(body:Customer,x_paari_admin_key:str|None=Header(None)):
    admin(x_paari_admin_key); return client().create_test_customer(body.username,body.first_name,body.last_name)
@router.post("/connect-url")
def connect(body:Connect,x_paari_admin_key:str|None=Header(None)):
    admin(x_paari_admin_key); return client().generate_connect_url(body.customer_id,body.redirect_uri)
@router.post("/customers/{customer_id}/refresh")
def refresh(customer_id:str,x_paari_admin_key:str|None=Header(None)):
    admin(x_paari_admin_key); return client().refresh_accounts(customer_id)
@router.get("/customers/{customer_id}/accounts")
def accounts(customer_id:str,x_paari_admin_key:str|None=Header(None)):
    admin(x_paari_admin_key); return normalize_accounts(client().accounts(customer_id))
@router.post("/transactions")
def transactions(body:Transactions,x_paari_admin_key:str|None=Header(None)):
    admin(x_paari_admin_key); return client().transactions(body.customer_id,body.account_id,body.from_date,body.to_date)
