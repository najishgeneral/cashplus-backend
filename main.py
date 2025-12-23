import os
from datetime import datetime, timedelta
from typing import Generator

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
bearer_scheme = HTTPBearer()
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr
#from pydantic import BaseModel, Field


from sqlalchemy import create_engine, String, DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import create_engine, String, DateTime, func, Integer

from sqlalchemy import Column, String, Text, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
#from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
import uuid

from sqlalchemy import Integer

from plaid.api import plaid_api
from plaid.configuration import Configuration
from plaid.api_client import ApiClient
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.accounts_get_request import AccountsGetRequest

from fastapi import Depends, HTTPException
#from pydantic import BaseModel
from pydantic import conint

import smtplib
from email.message import EmailMessage
from datetime import datetime, timezone
from fastapi import BackgroundTasks



# --------------------
# Config
# --------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
JWT_SECRET = os.getenv("JWT_SECRET", "").strip()

JWT_ALG = "HS256"
ACCESS_TOKEN_MINUTES = 60 * 24 * 7  # 7 days

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --------------------
# DB Models
# --------------------
class Base(DeclarativeBase):
    pass

from pydantic import BaseModel, Field
import re, uuid

class ManualBankRequest(BaseModel):
    bank_name: str = Field(..., min_length=2, max_length=80)
    account_name: str = Field(..., min_length=2, max_length=80)  # e.g. "Checking"
    routing_number: str = Field(..., min_length=9, max_length=9)
    account_number: str = Field(..., min_length=4, max_length=32)

def _digits_only(s: str) -> str:
    return re.sub(r"\D+", "", s or "")


class WithdrawRequest(BaseModel):
    amount_cents: conint(gt=0)
    bank_account_id: int


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Account(Base):
    __tablename__ = "accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(unique=True, index=True)
    balance_cents: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Transaction(Base):
    __tablename__ = "transactions"
    id: Mapped[int] = mapped_column(primary_key=True)

    # who initiated / owns this view of the transaction
    user_id: Mapped[int] = mapped_column(Integer, index=True)

    # "FUND" or "TRANSFER"
    type: Mapped[str] = mapped_column(String(20))

    # signed amount from THIS user's perspective:
    # +5000 for funding, -145 for sending, +145 for receiving
    amount_cents: Mapped[int] = mapped_column(Integer)

    #from sqlalchemy import ForeignKey
    #from sqlalchemy.orm import relationship

    bank_account_id: Mapped[int | None] = mapped_column(
        ForeignKey("linked_bank_accounts.id"),
        nullable=True,
        index=True,
    )
    
    bank_account = relationship("LinkedBankAccount")


    # optional counterparty info
    counterparty: Mapped[str | None] = mapped_column(String(64), nullable=True)
    counterparty_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    direction: Mapped[str] = mapped_column(String(8), default="IN")  # NE
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

# models (can live in main.py for now)

class PlaidItem(Base):
    __tablename__ = "plaid_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    item_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    access_token: Mapped[str] = mapped_column(Text, nullable=False)  # TODO: encrypt later

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


from sqlalchemy import String, Integer, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from datetime import datetime

class LinkedBankAccount(Base):
    __tablename__ = "linked_bank_accounts"

    id: Mapped[int] = mapped_column(primary_key=True)

    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)

    plaid_item_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    plaid_account_id: Mapped[str | None] = mapped_column(String, nullable=True)

    name: Mapped[str] = mapped_column(String, nullable=False)

    mask: Mapped[str | None] = mapped_column(String, nullable=True)
    subtype: Mapped[str | None] = mapped_column(String, nullable=True)
    institution: Mapped[str | None] = mapped_column(String, nullable=True)

    status: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default="ACTIVE",
        server_default="ACTIVE",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

Base.metadata.create_all(bind=engine)


# --------------------
# Schemas
# --------------------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class FundIn(BaseModel):
    amount_cents: int

class TransferIn(BaseModel):
    to_email: EmailStr
    amount_cents: int

# --------------------
# Helpers / deps
# --------------------
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_access_token(email: str) -> str:
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    payload = {"sub": email, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def get_or_create_account(db: Session, user_id: int) -> Account:
    acct = db.query(Account).filter(Account.user_id == user_id).first()
    if acct:
        return acct

    acct = Account(user_id=user_id, balance_cents=0)
    db.add(acct)

    try:
        # flush writes pending INSERTs so the row exists for the rest of this request,
        # without ending the transaction.
        db.flush()
        return acct
    except IntegrityError:
        # Another request created it at the same time
        db.rollback()
        acct = db.query(Account).filter(Account.user_id == user_id).first()
        if acct:
            return acct
        raise

def make_plaid_client():
    env = os.getenv("PLAID_ENV", "sandbox")
    host = {
        "sandbox": "https://sandbox.plaid.com",
        "development": "https://development.plaid.com",
        "production": "https://production.plaid.com",
    }[env]

    configuration = Configuration(
        host=host,
        api_key={
            "clientId": os.getenv("PLAID_CLIENT_ID"),
            "secret": os.getenv("PLAID_SECRET"),
        }
    )
    api_client = ApiClient(configuration)
    return plaid_api.PlaidApi(api_client)

plaid_client = make_plaid_client()


def send_email(to_email: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    email_from = os.getenv("EMAIL_FROM") or username  # fallback

    if not (host and port and username and password and email_from):
        # Fail loudly in logs so you can see missing env vars
        raise RuntimeError("Missing SMTP env vars (SMTP_HOST/PORT/USERNAME/PASSWORD/EMAIL_FROM)")

    msg = EmailMessage()
    msg["From"] = email_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    # Gmail SMTP (STARTTLS)
    with smtplib.SMTP(host, port) as server:
        server.ehlo()
        server.starttls()
        server.login(username, password)
        server.send_message(msg)


# --------------------
# App
# --------------------
app = FastAPI(title="CashPlus API")

# For Expo dev you can leave this open; tighten later
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"name": "CashPlus API", "ok": True}


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/auth/register")
def register(body: RegisterIn, db: Session = Depends(get_db)):
    email = body.email.lower().strip()

    if len(body.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user = User(email=email, password_hash=pwd_context.hash(body.password))
    db.add(user)
    try:
        db.commit()
        db.refresh(user)  # <-- IMPORTANT so user.id is available
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")

    account = Account(user_id=user.id, balance_cents=0)
    db.add(account)
    db.commit()

    return {"status": "registered"}

@app.get("/fbo_total")
def fbo_total(db: Session = Depends(get_db)):
    total = db.query(func.coalesce(func.sum(Account.balance_cents), 0)).scalar()
    return {"fbo_total_cents": int(total or 0)}

@app.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    email = body.email.lower().strip()
    user = db.query(User).filter(User.email == email).first()

    if not user or not pwd_context.verify(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return TokenOut(access_token=create_access_token(user.email))


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "created_at": user.created_at}

@app.post("/fund")
def fund(
    body: FundIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.amount_cents <= 0:
        raise HTTPException(status_code=400, detail="amount_cents must be > 0")

    account = get_or_create_account(db, user.id)

    account.balance_cents += body.amount_cents

    db.add(
        Transaction(
            user_id=user.id,
            type="FUND",
            amount_cents=body.amount_cents,
            direction="IN",
            counterparty="BANK",
            # if you also have counterparty_email column, you can set it to None or omit
        )
    )

    db.commit()

    return {"status": "funded", "balance_cents": account.balance_cents}

import os, smtplib
from email.message import EmailMessage

def send_email(to_email: str, subject: str, body: str):
    try:
        host = os.environ["SMTP_HOST"]
        port = int(os.environ.get("SMTP_PORT", "587"))
        username = os.environ["SMTP_USERNAME"]
        password = os.environ["SMTP_PASSWORD"]
        email_from = os.environ["EMAIL_FROM"]

        msg = EmailMessage()
        msg["From"] = email_from
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)

        print(f"[EMAIL] Sending to={to_email} subject={subject}")

        with smtplib.SMTP(host, port, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(username, password)
            server.send_message(msg)

        print(f"[EMAIL] Sent OK to={to_email}")

    except Exception as e:
        print(f"[EMAIL] FAILED to={to_email} err={repr(e)}")
        raise


class TransferRequest(BaseModel):
    receiver_email: str = Field(..., min_length=3, max_length=320)
    amount_cents: int = Field(..., gt=0)


from fastapi import BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

@app.post("/transfer")
def transfer(
    body: TransferIn,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.amount_cents <= 0:
        raise HTTPException(status_code=400, detail="amount_cents must be > 0")

    to_email = body.to_email.lower().strip()
    if to_email == user.email:
        raise HTTPException(status_code=400, detail="Cannot transfer to yourself")

    to_user = db.query(User).filter(User.email == to_email).first()
    if not to_user:
        raise HTTPException(status_code=404, detail="Recipient not found")

    from_acct = get_or_create_account(db, user.id)
    to_acct = get_or_create_account(db, to_user.id)

    if from_acct.balance_cents < body.amount_cents:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    from_acct.balance_cents -= body.amount_cents
    to_acct.balance_cents += body.amount_cents

    db.add(Transaction(
        user_id=user.id,
        type="XFER_OUT",
        amount_cents=body.amount_cents,
        direction="OUT",
        counterparty="USER",
        counterparty_email=to_email,
    ))

    db.add(Transaction(
        user_id=to_user.id,
        type="XFER_IN",
        amount_cents=body.amount_cents,
        direction="IN",
        counterparty="USER",
        counterparty_email=user.email,
    ))

    db.commit()
    db.refresh(from_acct)
    db.refresh(to_acct)

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    amount_str = f"${body.amount_cents / 100:.2f}"

    # schedule emails AFTER commit
    background_tasks.add_task(
        send_email,
        user.email,
        "CashPlus transfer sent",
        f"You have sent {amount_str} to {to_user.email} on {now_str}."
    )
    background_tasks.add_task(
        send_email,
        to_user.email,
        "CashPlus transfer received",
        f"You have received {amount_str} from {user.email} on {now_str}."
    )

    return {
        "ok": True,
        "to_email": to_user.email,
        "amount_cents": body.amount_cents,
        "sender_balance_cents": from_acct.balance_cents,
        "receiver_balance_cents": to_acct.balance_cents,
    }



    #return {"ok": True}


    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    amount = f"${req.amount_cents/100:.2f}"

    sender_email = user.email
    receiver_email = receiver.email  # however you looked them up

    background_tasks.add_task(
        send_email,
        sender_email,
        "CashPlus transfer sent",
        f"You have sent {amount} to {receiver_email} on {now_str}."
    )

    background_tasks.add_task(
        send_email,
        receiver_email,
        "CashPlus transfer received",
        f"You have received {amount} from {sender_email} on {now_str}."
    )


    return {
        "status": "transferred",
        "from_balance_cents": from_acct.balance_cents,
        "to_email": to_email,
        "amount_cents": body.amount_cents,
    }


@app.get("/balance")
def get_balance(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    account = get_or_create_account(db, user.id)
    return {"balance_cents": account.balance_cents}


@app.get("/transactions")
def transactions(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = (
        db.query(Transaction)
        .filter(Transaction.user_id == user.id)
        .order_by(Transaction.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": r.id,
            "type": r.type,
            "amount_cents": r.amount_cents,
            "counterparty_email": r.counterparty_email,
            "created_at": r.created_at,
        }
        for r in rows
    ]

#from fastapi import Depends, HTTPException
#from pydantic import BaseModel

class ExchangePublicTokenIn(BaseModel):
    public_token: str

@app.post("/bank/link_token")
def create_link_token(
    db: Session = Depends(get_db),
    user=Depends(get_current_user),  # whatever you use to get current user. Changed required_user to get_current_user
):
    try:
        req = LinkTokenCreateRequest(
            user=LinkTokenCreateRequestUser(client_user_id=str(user.id)),
            client_name="CashPlus",
            products=[Products("auth")],   # "auth" is common for bank acct verification
            country_codes=[CountryCode("US")],
            language="en",
        )
        resp = plaid_client.link_token_create(req)
        return {"link_token": resp["link_token"]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Plaid link_token error: {e}")

@app.post("/bank/exchange_public_token")
def exchange_public_token(
    body: ExchangePublicTokenIn,
    db: Session = Depends(get_db),
    user=Depends(get_current_user), #changed required_user to get_current_user
):
    try:
        exchange_req = ItemPublicTokenExchangeRequest(public_token=body.public_token)
        exchange_resp = plaid_client.item_public_token_exchange(exchange_req)
        access_token = exchange_resp["access_token"]
        item_id = exchange_resp["item_id"]

        # Upsert PlaidItem for user + item_id
        item = db.query(PlaidItem).filter(PlaidItem.item_id == item_id).one_or_none()
        if not item:
            item = PlaidItem(user_id=user.id, item_id=item_id, access_token=access_token)
            db.add(item)
            db.flush()  # get item.id
        else:
            item.access_token = access_token
            item.user_id = user.id

        # Fetch accounts
        acct_req = AccountsGetRequest(access_token=access_token)
        acct_resp = plaid_client.accounts_get(acct_req)
        accounts = acct_resp["accounts"]

        saved = []
        for a in accounts:
            plaid_account_id = a["account_id"]
            name = a.get("name") or "Bank account"
            mask = a.get("mask")
            subtype = a.get("subtype")

            existing = (
                db.query(LinkedBankAccount)
                .filter(
                    LinkedBankAccount.user_id == user.id,
                    LinkedBankAccount.plaid_account_id == plaid_account_id,
                )
                .one_or_none()
            )
            if not existing:
                existing = LinkedBankAccount(
                    user_id=user.id,
                    plaid_item_id=item.id,
                    plaid_account_id=plaid_account_id,
                    name=name,
                    mask=mask,
                    subtype=subtype,
                    status="active",
                )
                db.add(existing)

            saved.append({
                "id": str(existing.id),
                "name": name,
                "mask": mask,
                "subtype": subtype,
            })

        db.commit()
        return {"linked_accounts": saved}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Plaid exchange error: {e}")

@app.post("/withdraw")
def withdraw(req: WithdrawRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    # 1) Verify bank account belongs to the user . changed required_user to get_current_user above
    bank = db.query(LinkedBankAccount).filter(
        LinkedBankAccount.id == req.bank_account_id,
        LinkedBankAccount.user_id == user.id
    ).first()

    if not bank:
        raise HTTPException(status_code=404, detail="Bank account not found")

    # 2) Check balance
    acct = db.query(Account).filter(Account.user_id == user.id).first()
    if not acct:
        raise HTTPException(status_code=404, detail="Account not found")

    if acct.balance_cents < req.amount_cents:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    # 3) Deduct balance
    acct.balance_cents -= req.amount_cents

    # 4) Record transaction
    tx = Transaction(
        user_id=user.id,
        type="WITHDRAW",
        amount_cents=-req.amount_cents,      # negative from user perspective
        direction="OUT",
        bank_account_id=bank.id,
        counterparty=bank.name if hasattr(bank, "name") else "BANK",
        counterparty_email=None,
    )

    db.add(tx)
    db.commit()
    db.refresh(tx)
    db.refresh(acct)

    return {
        "ok": True,
        "balance_cents": acct.balance_cents,
        "withdrawal": {
            "transaction_id": tx.id,
            "bank_account_id": bank.id,
            "amount_cents": req.amount_cents,
            "status": "PENDING"  # for now simulated
        }
    }

@app.get("/bank/accounts")
def list_bank_accounts(db: Session = Depends(get_db), user=Depends(get_current_user)): #Changed required_user to get_current_user
    rows = db.query(LinkedBankAccount).filter(LinkedBankAccount.user_id == user.id).all()

    return [
        {
            "id": r.id,
            "name": getattr(r, "name", None),
            "mask": getattr(r, "mask", None),
            "subtype": getattr(r, "subtype", None),
            "status": getattr(r, "status", "active"),
        }
        for r in rows
    ]

@app.get("/linked-bank-accounts")
def list_linked_banks(db: Session = Depends(get_db), user=Depends(get_current_user)):
    banks = (
        db.query(LinkedBankAccount)
        .filter(
            LinkedBankAccount.user_id == user.id,
            LinkedBankAccount.status == "ACTIVE",    
        )
        .order_by(LinkedBankAccount.id.desc())
        .all()
    )
    return [
        {
            "id": b.id,
            "name": getattr(b, "name", None),
            "mask": getattr(b, "mask", None),
            "institution": getattr(b, "institution", None),
            "created_at": b.created_at,
        }
        for b in banks
    ]

@app.post("/linked-bank-accounts/demo")
def add_demo_bank(db: Session = Depends(get_db), user=Depends(get_current_user)):
    bank = LinkedBankAccount(
        user_id=user.id,
	plaid_item_id=None,
        name="Demo Checking",
        mask="1234",
        institution="Demo Bank",
	status="ACTIVE",
    )
    db.add(bank)
    db.commit()
    db.refresh(bank)
    return {
        "id": bank.id,
        "name": bank.name,
        "mask": bank.mask,
        "institution": bank.institution,
    }

@app.post("/linked-bank-accounts/manual")
def add_manual_bank(req: ManualBankRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):  #replaced require_user
    routing = _digits_only(req.routing_number)
    acct = _digits_only(req.account_number)

    if len(routing) != 9:
        raise HTTPException(status_code=400, detail="Routing number must be 9 digits")
    if len(acct) < 4:
        raise HTTPException(status_code=400, detail="Account number must be at least 4 digits")

    mask = acct[-4:]

    # IMPORTANT:
    # We do NOT store full account numbers in Postgres.
    # For demo/manual banks we store only last4 + a name.
    # For real bank linking later, Plaid will provide tokens/ids.

    manual_plaid_item_id = 0  # safe dummy for NOT NULL
    manual_plaid_account_id = f"manual_{uuid.uuid4().hex}"  # safe dummy for NOT NULL

    bank = LinkedBankAccount(
        user_id=user.id,
        institution=req.bank_name,
        name=req.account_name,
        mask=mask,
        plaid_item_id=None,                     # real fix
        plaid_account_id=f"manual_{uuid.uuid4().hex}",
        status="ACTIVE",
    )


    db.add(bank)
    db.commit()
    db.refresh(bank)

    return {
        "id": bank.id,
        "name": getattr(bank, "name", None),
        "mask": getattr(bank, "mask", None),
        "institution": getattr(bank, "institution", None),
        "created_at": bank.created_at,
        "status": getattr(bank, "status", "ACTIVE"),
    }

@app.delete("/linked-bank-accounts/{bank_id}")
def delete_bank(bank_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    bank = (
        db.query(LinkedBankAccount)
        .filter(
            LinkedBankAccount.id == bank_id,
            LinkedBankAccount.user_id == user.id,
        )
        .first()
    )

    if not bank:
        raise HTTPException(status_code=404, detail="Bank account not found")

    # Soft delete: preserve history
    bank.status = "DELETED"
    db.add(bank)
    db.commit()

    return {"ok": True}


