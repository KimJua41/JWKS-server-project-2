from datetime import datetime, timedelta, timezone
from typing import Dict, List
import uuid
import sqlite3

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
from jwt import PyJWK
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# --------------------------------------------------------------------
# Config
# --------------------------------------------------------------------

JWT_ISSUER = "example-issuer"
JWT_AUDIENCE = "example-audience"
JWT_LIFETIME_SECONDS = 300  # 5 minutes

# Key lifetime in the DB (used to decide expired vs unexpired keys)
# For this project, we only need "expired" vs "valid" based on exp in DB.
KEY_EXPIRED_OFFSET_SECONDS = -10          # expired key: now - 10 seconds
KEY_VALID_OFFSET_SECONDS = 3600           # valid key: now + 1 hour

ALGORITHM = "RS256"

DB_PATH = "totally_not_my_privateKeys.db"

# --------------------------------------------------------------------
# Models
# --------------------------------------------------------------------


class KeyEntry(BaseModel):
    kid: str
    private_pem: str
    expires_at: datetime


# --------------------------------------------------------------------
# SQLite-backed key store
# --------------------------------------------------------------------


class DBKeyStore:
    """
    SQLite-backed key store.

    - Uses file: totally_not_my_privateKeys.db
    - Table schema:
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )

    - On initialization, ensures at least:
        * one expired key (exp <= now)
        * one valid key (exp >= now + 1 hour)
    """

    def __init__(self, db_path: str) -> None:
        # Single connection for this simple app
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_table()
        self._ensure_seed_keys()

    def _create_table(self) -> None:
        """
        Create the keys table if it does not exist.
        """
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key BLOB NOT NULL,
                exp INTEGER NOT NULL
            )
            """
        )
        self._conn.commit()

    def _insert_key(self, exp_ts: int) -> int:
        """
        Generate a new RSA private key, serialize it to PEM, and insert into DB.

        Returns the new row's kid.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        cur = self._conn.cursor()
        # Use parameterized query to avoid SQL injection
        cur.execute(
            "INSERT INTO keys(key, exp) VALUES(?, ?)",
            (private_pem, exp_ts),
        )
        self._conn.commit()
        return cur.lastrowid

    def _ensure_seed_keys(self) -> None:
        """
        Ensure there is at least one expired key and one valid key in the DB.
        """
        now_ts = int(datetime.now(timezone.utc).timestamp())

        # Check for at least one expired key
        cur = self._conn.cursor()
        cur.execute(
            "SELECT kid FROM keys WHERE exp <= ? LIMIT 1",
            (now_ts,),
        )
        expired_exists = cur.fetchone() is not None

        # Check for at least one valid key (exp >= now + 1 hour)
        cur.execute(
            "SELECT kid FROM keys WHERE exp >= ? LIMIT 1",
            (now_ts + KEY_VALID_OFFSET_SECONDS,),
        )
        valid_exists = cur.fetchone() is not None

        if not expired_exists:
            exp_ts = now_ts + KEY_EXPIRED_OFFSET_SECONDS
            self._insert_key(exp_ts)

        if not valid_exists:
            exp_ts = now_ts + KEY_VALID_OFFSET_SECONDS
            self._insert_key(exp_ts)

    def get_key(self, expired: bool) -> KeyEntry:
        """
        Return a single key from the DB.

        - If expired=False: return a valid (unexpired) key (exp > now).
        - If expired=True: return an expired key (exp <= now).
        """
        now_ts = int(datetime.now(timezone.utc).timestamp())
        cur = self._conn.cursor()

        if expired:
            # Most recently expired key
            cur.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp <= ?
                ORDER BY exp DESC
                LIMIT 1
                """,
                (now_ts,),
            )
        else:
            # Soonest-to-expire valid key
            cur.execute(
                """
                SELECT kid, key, exp
                FROM keys
                WHERE exp > ?
                ORDER BY exp ASC
                LIMIT 1
                """,
                (now_ts,),
            )

        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=500, detail="No suitable key available")

        kid = str(row["kid"])
        private_pem = row["key"]
        exp_dt = datetime.fromtimestamp(row["exp"], tz=timezone.utc)

        return KeyEntry(kid=kid, private_pem=private_pem, expires_at=exp_dt)

    def get_unexpired_public_jwks(self) -> Dict:
        """
        Return JWKS containing only unexpired public keys.

        Reads private keys from DB, derives public keys, and converts to JWK.
        """
        now_ts = int(datetime.now(timezone.utc).timestamp())
        cur = self._conn.cursor()
        cur.execute(
            """
            SELECT kid, key, exp
            FROM keys
            WHERE exp > ?
            """,
            (now_ts,),
        )
        rows = cur.fetchall()

        keys: List[Dict] = []

        for row in rows:
            kid = str(row["kid"])
            private_pem = row["key"]

            # Load private key and derive public key
            private_key = serialization.load_pem_private_key(
                private_pem.encode("utf-8"),
                password=None,
            )
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            # Convert PEM to JWK
            jwk_obj = PyJWK.from_buffer(public_pem.encode("utf-8"))
            jwk_dict = jwk_obj.to_dict()
            jwk_dict["kid"] = kid
            jwk_dict["alg"] = ALGORITHM
            jwk_dict["use"] = "sig"
            keys.append(jwk_dict)

        return {"keys": keys}


# --------------------------------------------------------------------
# JWT helpers
# --------------------------------------------------------------------


def create_jwt_for_key(entry: KeyEntry, expired: bool = False) -> str:
    """
    Create a JWT signed with the given key.

    If expired=True, the 'exp' claim will be in the past.
    """
    now = datetime.now(timezone.utc)
    if expired:
        exp = now - timedelta(seconds=60)
    else:
        exp = now + timedelta(seconds=JWT_LIFETIME_SECONDS)

    payload = {
        "sub": "fake-user-id",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    token = jwt.encode(
        payload,
        entry.private_pem,
        algorithm=ALGORITHM,
        headers={"kid": entry.kid},
    )
    return token


# --------------------------------------------------------------------
# FastAPI app and routes
# --------------------------------------------------------------------

key_store = DBKeyStore(DB_PATH)
app = FastAPI()


@app.get("/.well-known/jwks.json")
def jwks():
    """
    JWKS endpoint.

    Returns only unexpired public keys in JWKS format.
    """
    jwks_body = key_store.get_unexpired_public_jwks()
    return JSONResponse(content=jwks_body)


@app.get("/jwks")
def jwks_legacy():
    """
    Legacy JWKS endpoint kept for backward compatibility with existing tests.
    """
    jwks_body = key_store.get_unexpired_public_jwks()
    return JSONResponse(content=jwks_body)


@app.post("/auth")
def auth(expired: bool = Query(default=False)):
    """
    Authentication endpoint.

    - Always returns a JWT (no real auth for this assignment).
    - If expired=false (default): sign with an unexpired key and unexpired exp.
    - If expired=true: sign with an expired key and expired exp.
    """
    key_entry = key_store.get_key(expired=expired)
    token = create_jwt_for_key(key_entry, expired=expired)
    return {"access_token": token, "token_type": "bearer"}


# --------------------------------------------------------------------
# Entry point for running
# --------------------------------------------------------------------
# Run with:
#   uvicorn main:app --host 0.0.0.0 --port 8080
# The assignment specifies port 8080, so use that when starting uvicorn.