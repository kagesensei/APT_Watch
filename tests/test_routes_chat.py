from app import chat as chat_module


class TestChatIndex:
    def test_chat_home_page_renders(self, client):
        assert client.get("/").status_code == 200


class TestAsk:
    def test_empty_message_is_a_400(self, client):
        resp = client.post("/ask", json={"message": "  "})
        assert resp.status_code == 400

    def test_missing_body_is_a_400(self, client):
        resp = client.post("/ask", data="not json", content_type="text/plain")
        assert resp.status_code == 400

    def test_known_technique_question_answers_using_the_mocked_llm(self, client, db, monkeypatch):
        technique_id = db.execute(
            "SELECT DISTINCT technique_id FROM technique_mitigation LIMIT 1"
        ).fetchone()[0]

        captured = {}

        def fake_answer(question, facts):
            captured["facts"] = facts
            return f"Canned answer citing {technique_id}."

        monkeypatch.setattr(chat_module.llm, "answer", fake_answer)

        resp = client.post("/ask", json={"message": f"What mitigates {technique_id}?"})
        assert resp.status_code == 200
        payload = resp.get_json()
        assert technique_id in payload["entities"]["techniques"]
        assert payload["answer"] == f"Canned answer citing {technique_id}."
        assert f'data-id="{technique_id}"' in payload["answer_html"]
        assert captured["facts"], "facts retrieved for the technique should be passed to llm.answer"

    def test_question_with_no_recognizable_entity_and_no_general_keyword_yields_no_facts(
        self, client, monkeypatch
    ):
        monkeypatch.setattr(chat_module.llm, "answer", lambda q, facts: "no data" if not facts else "unexpected")
        resp = client.post("/ask", json={"message": "asdkjaslkdj random gibberish"})
        assert resp.status_code == 200
        assert resp.get_json()["answer"] == "no data"

    def test_general_overview_question_falls_back_to_recent_kev(self, client, monkeypatch):
        captured = {}

        def fake_answer(question, facts):
            captured["facts"] = facts
            return "summary"

        monkeypatch.setattr(chat_module.llm, "answer", fake_answer)
        resp = client.post("/ask", json={"message": "What's concerning right now?"})
        assert resp.status_code == 200
        assert captured["facts"], "general-overview questions should fall back to lookup_recent_kev"

    def test_follow_up_resolves_entity_from_history(self, client, db, monkeypatch):
        cve_id = db.execute("SELECT cve_id FROM kev LIMIT 1").fetchone()[0]
        monkeypatch.setattr(chat_module.llm, "answer", lambda q, facts: "ok")
        from app import intel
        monkeypatch.setattr(intel, "fetch_nvd", lambda cve_id, cache: None)

        resp = client.post("/ask", json={
            "message": "what mitigates this?",
            "history": [f"Tell me about {cve_id}"],
        })
        assert resp.status_code == 200
        assert resp.get_json()["entities"]["cves"] == [cve_id]

    def test_missing_model_file_surfaces_as_500_with_message(self, client, db, monkeypatch):
        technique_id = db.execute(
            "SELECT DISTINCT technique_id FROM technique_mitigation LIMIT 1"
        ).fetchone()[0]

        def raise_not_found(question, facts):
            raise FileNotFoundError("No LLM model found at models/fake.gguf")

        monkeypatch.setattr(chat_module.llm, "answer", raise_not_found)
        resp = client.post("/ask", json={"message": f"What mitigates {technique_id}?"})
        assert resp.status_code == 500
        assert "No LLM model found" in resp.get_json()["error"]


class TestSavedChatsRequireLogin:
    def test_list_chats_requires_login(self, client):
        assert client.get("/api/chats").status_code == 401

    def test_get_chat_requires_login(self, client):
        assert client.get("/api/chats/some-id").status_code == 401

    def test_put_chat_requires_login(self, client):
        assert client.put("/api/chats/some-id", json={"messages": []}).status_code == 401

    def test_delete_chat_requires_login(self, client):
        assert client.delete("/api/chats/some-id").status_code == 401


class TestSavedChatsSignedIn:
    def _sign_in(self, client, user_id="user123"):
        with client.session_transaction() as sess:
            sess["user"] = {"id": user_id, "name": "Test User", "email": "test@example.com"}

    def test_create_list_get_and_delete_a_chat(self, client):
        self._sign_in(client)

        put_resp = client.put(
            "/api/chats/chat-1",
            json={"messages": [{"role": "user", "content": "Hello there"}]},
        )
        assert put_resp.status_code == 200
        assert put_resp.get_json()["title"] == "Hello there"

        list_resp = client.get("/api/chats")
        assert list_resp.status_code == 200
        ids = [c["id"] for c in list_resp.get_json()]
        assert "chat-1" in ids

        get_resp = client.get("/api/chats/chat-1")
        assert get_resp.status_code == 200
        assert get_resp.get_json()["messages"][0]["content"] == "Hello there"

        delete_resp = client.delete("/api/chats/chat-1")
        assert delete_resp.status_code == 200
        assert client.get("/api/chats/chat-1").status_code == 404

    def test_get_missing_chat_is_404(self, client):
        self._sign_in(client)
        assert client.get("/api/chats/does-not-exist").status_code == 404

    def test_put_without_messages_is_400(self, client):
        self._sign_in(client)
        resp = client.put("/api/chats/chat-2", json={"title": "x"})
        assert resp.status_code == 400
