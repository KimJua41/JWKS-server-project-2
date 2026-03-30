# to test for a valid key:
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_jwks_endpoint_structure():
    response = client.get("/jwks")
    assert response.status_code == 200

    body = response.json()
    assert "keys" in body
    assert isinstance(body["keys"], list)

    # If a key exists, ensure required fields are present
    if body["keys"]:
        key = body["keys"][0]
        assert "kid" in key
        assert "kty" in key
        assert "n" in key
        assert "e" in key
        assert "alg" in key
        assert "use" in key