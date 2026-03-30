import jwt
from fastapi.testclient import TestClient
from main import app, JWT_ISSUER, JWT_AUDIENCE, ALGORITHM

client = TestClient(app)


def test_auth_returns_valid_jwt():
    # POST /auth with no body
    response = client.post("/auth")
    assert response.status_code == 200

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    token = data["access_token"]

    # Decode header to extract kid
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    kid = header["kid"]

    # Decode payload (skip verification for now)
    payload = jwt.decode(token, options={"verify_signature": False})
    assert payload["iss"] == JWT_ISSUER
    assert payload["aud"] == JWT_AUDIENCE
    assert "exp" in payload
    assert "iat" in payload
    assert payload["sub"] == "fake-user-id"

    # Now fetch JWKS and ensure the key is present
    jwks_resp = client.get("/jwks")
    assert jwks_resp.status_code == 200
    jwks = jwks_resp.json()

    # Ensure JWKS contains the kid
    kids = [k["kid"] for k in jwks["keys"]]
    assert kid in kids


def test_auth_expired_token():
    # Request an expired token
    response = client.post("/auth?expired=true")
    assert response.status_code == 200

    token = response.json()["access_token"]

    # Decode without verifying signature
    payload = jwt.decode(token, options={"verify_signature": False})

    # exp should be in the past
    assert payload["exp"] < payload["iat"]