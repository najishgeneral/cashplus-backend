import os
from datetime import datetime, timedelta
from typing import Generator

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
bearer_scheme = HTTPBearer()
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

from sqlalchemy import create_engine, String, DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy import create_engine, String, DateTime, func, Integer

from sqlalchemy import Column, String, Text, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from plaid.api import plaid_api
from plaid.configuration import Configuration
from plaid.api_client import ApiClient
from plaid.model.link_token_create_request import LinkTokenCreateRequest
from plaid.model.link_token_create_request_user import LinkTokenCreateRequestUser
from plaid.model.products import Products
from plaid.model.country_code import CountryCode
from plaid.model.item_public_token_exchange_request import ItemPublicTokenExchangeRequest
from plaid.model.accounts_get_request import AccountsGetRequest

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

    # optional counterparty info
    counterparty: Mapped[str | None] = mapped_column(String(64), nullable=True)
    counterparty_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    direction: Mapped[str] = mapped_column(String(8), default="IN")  # NE
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

# models (can live in main.py for now)

from sqlalchemy import Column, String, Text, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

class PlaidItem(Base):
    __tablename__ = "plaid_items"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    item_id = Column(String, unique=True, nullable=False)
    access_token = Column(Text, nullable=False)  # TODO: encrypt in prod

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class LinkedBankAccount(Base):
    __tablename__ = "linked_bank_accounts"
    __table_args__ = (
        UniqueConstraint("user_id", "plaid_account_id", name="uq_user_plaid_account"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    plaid_item_id = Column(UUID(as_uuid=True), ForeignKey("plaid_items.id", ondelete="CASCADE"), nullable=False)

    plaid_account_id = Column(String, nullable=False)
    name = Column(String, nullable=False)
    mask = Column(String, nullable=True)
    subtype = Column(String, nullable=True)  # checking/savings, etc.
    status = Column(String, nullable=False, default="active")

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


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

@app.post("/transfer")
def transfer(
    body: TransferIn,
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

    db.add(
        Transaction(
            user_id=user.id,
            type="XFER_OUT",
            amount_cents=body.amount_cents,
            direction="OUT",
            counterparty="USER",
            counterparty_email=to_email,   # only if the column exists in DB
        )
    )
    db.add(
        Transaction(
            user_id=to_user.id,
            type="XFER_IN",
            amount_cents=body.amount_cents,
            direction="IN",
            counterparty="USER",
            counterparty_email=user.email, # only if the column exists in DB
        )
    )

    db.commit()

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

from fastapi import Depends, HTTPException
from pydantic import BaseModel

class ExchangePublicTokenIn(BaseModel):
    public_token: str

@app.post("/bank/link_token")
def create_link_token(
    db: Session = Depends(get_db),
    user=Depends(require_user),  # whatever you use to get current user
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
    user=Depends(require_user),
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
