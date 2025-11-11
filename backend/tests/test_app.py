# backend/tests/test_app.py
from app import app

def test_health_endpoint():
    client = app.test_client()
    response = client.get("/health")  # replace with an actual route
    assert response.status_code == 200
