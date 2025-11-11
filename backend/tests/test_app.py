from app import app

def test_homepage():
    client = app.test_client()
    response = client.get("/health")  # or "/" if you have a root route
    assert response.status_code == 200
