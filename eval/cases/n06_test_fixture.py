def test_login(client):
    resp = client.post("/login", data={"username": "alice", "password": "test-password"})
    assert resp.status_code == 200
