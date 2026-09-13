(function () {
  const log = document.getElementById("chat-log");
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const chatListEl = document.getElementById("chat-list");
  const newChatBtn = document.getElementById("new-chat-btn");
  const viewPanel = document.getElementById("view-panel");

  const isAuthenticated = !!window.APTWATCH_USER;
  let currentChatId = null;
  let messages = []; // {role: "user"|"assistant", content, html, sources}

  // --- Storage: server-backed for signed-in users, sessionStorage (cleared
  // when the browser session ends) for anonymous users. Same interface either
  // way so the rest of this file doesn't need to know which one is active. ---

  function sessionStorageStore() {
    const KEY = "aptwatch_chats";
    function readAll() {
      try {
        return JSON.parse(sessionStorage.getItem(KEY) || "{}");
      } catch (e) {
        return {};
      }
    }
    function writeAll(all) {
      try {
        sessionStorage.setItem(KEY, JSON.stringify(all));
      } catch (e) {
        // storage unavailable/full - saved chats just won't persist this session
      }
    }
    return {
      list() {
        const all = readAll();
        const rows = Object.keys(all).map(function (id) {
          return { id: id, title: all[id].title, updated_at: all[id].updated_at };
        });
        rows.sort(function (a, b) { return a.updated_at < b.updated_at ? 1 : -1; });
        return Promise.resolve(rows);
      },
      get(id) {
        const all = readAll();
        return Promise.resolve(all[id] ? Object.assign({ id: id }, all[id]) : null);
      },
      save(id, title, msgs) {
        const all = readAll();
        all[id] = { title: title, messages: msgs, updated_at: new Date().toISOString() };
        writeAll(all);
        return Promise.resolve({ id: id, title: title });
      },
      remove(id) {
        const all = readAll();
        delete all[id];
        writeAll(all);
        return Promise.resolve({ deleted: id });
      },
    };
  }

  function serverStore() {
    return {
      list() {
        return fetch("/api/chats").then(function (r) { return r.ok ? r.json() : []; });
      },
      get(id) {
        return fetch("/api/chats/" + encodeURIComponent(id)).then(function (r) {
          return r.ok ? r.json() : null;
        });
      },
      save(id, title, msgs) {
        return fetch("/api/chats/" + encodeURIComponent(id), {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ title: title, messages: msgs }),
        }).then(function (r) { return r.json(); });
      },
      remove(id) {
        return fetch("/api/chats/" + encodeURIComponent(id), { method: "DELETE" }).then(function (r) {
          return r.json();
        });
      },
    };
  }

  const store = isAuthenticated ? serverStore() : sessionStorageStore();

  // --- Sidebar ---

  function renderSidebar() {
    store.list().then(function (rows) {
      chatListEl.innerHTML = "";
      if (rows.length === 0) {
        const empty = document.createElement("p");
        empty.className = "chat-list-empty";
        empty.textContent = "No saved chats yet.";
        chatListEl.appendChild(empty);
        return;
      }
      rows.forEach(function (row) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "chat-list-item" + (row.id === currentChatId ? " active" : "");
        btn.textContent = row.title || "Untitled chat";
        btn.addEventListener("click", function () { loadChat(row.id); });
        chatListEl.appendChild(btn);
      });
    });
  }

  function loadChat(id) {
    store.get(id).then(function (chat) {
      if (!chat) return;
      currentChatId = id;
      messages = chat.messages || [];
      renderMessages();
      renderSidebar();
    });
  }

  function startNewChat() {
    currentChatId = null;
    messages = [];
    renderMessages();
    renderSidebar();
    input.focus();
  }

  function persistChat() {
    if (messages.length === 0) return;
    if (!currentChatId) {
      currentChatId = crypto.randomUUID();
    }
    const firstUser = messages.find(function (m) { return m.role === "user"; });
    const title = firstUser ? firstUser.content.slice(0, 60) : "New chat";
    store.save(currentChatId, title, messages).then(renderSidebar);
  }

  // --- Message rendering ---

  function renderMessages() {
    log.innerHTML = "";
    if (messages.length === 0) {
      renderSuggestions();
      return;
    }
    messages.forEach(function (m) {
      if (m.role === "user") {
        appendBubble("user", m.content);
      } else {
        const bubble = appendBubble("assistant", null);
        bubble.innerHTML = m.html || escapeText(m.content);
        addSources(m.sources);
      }
    });
    log.scrollTop = log.scrollHeight;
  }

  function renderSuggestions() {
    const wrap = document.createElement("div");
    wrap.className = "chat-suggestions";
    const title = document.createElement("span");
    title.className = "chat-suggestions-title";
    title.textContent = "Try asking:";
    wrap.appendChild(title);
    [
      "What's a concerning CVE being actively exploited right now?",
      "What TTPs exploit CVE-2024-3400 and how do I mitigate it?",
      "What mitigates T1055?",
      "What techniques does APT29 use?",
    ].forEach(function (text) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "chat-suggestion";
      btn.textContent = text;
      btn.addEventListener("click", function () { ask(text); });
      wrap.appendChild(btn);
    });
    log.appendChild(wrap);
  }

  function removeSuggestions() {
    const el = log.querySelector(".chat-suggestions");
    if (el) el.remove();
  }

  function escapeText(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  function appendBubble(role, text) {
    const el = document.createElement("div");
    el.className = "chat-message chat-message-" + role;
    if (text !== null) el.textContent = text;
    log.appendChild(el);
    log.scrollTop = log.scrollHeight;
    return el;
  }

  function addSources(sources) {
    if (!sources || sources.length === 0) return;
    const wrap = document.createElement("div");
    wrap.className = "chat-sources";
    const title = document.createElement("div");
    title.className = "chat-sources-title";
    title.textContent = "Sources";
    wrap.appendChild(title);

    const list = document.createElement("ul");
    sources.forEach(function (s) {
      const li = document.createElement("li");
      if (s.url) {
        const a = document.createElement("a");
        a.href = s.url;
        a.target = "_blank";
        a.rel = "noopener";
        a.textContent = s.dataset + ": " + s.name;
        li.appendChild(a);
      } else {
        li.textContent = s.dataset + ": " + s.name;
      }
      list.appendChild(li);
    });
    wrap.appendChild(list);
    log.appendChild(wrap);
    log.scrollTop = log.scrollHeight;
  }

  // --- Ask ---

  function ask(message) {
    removeSuggestions();
    appendBubble("user", message);
    messages.push({ role: "user", content: message });
    input.value = "";
    input.disabled = true;
    const pending = appendBubble("assistant", "Thinking...");

    const history = messages.filter(function (m) { return m.role === "user"; }).map(function (m) { return m.content; });

    fetch("/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: message, history: history }),
    })
      .then(function (resp) {
        return resp.json().then(function (data) {
          return { ok: resp.ok, data: data };
        });
      })
      .then(function (result) {
        if (!result.ok) {
          pending.textContent = "Error: " + (result.data.error || "something went wrong.");
          pending.classList.add("chat-message-error");
          messages.pop(); // don't persist a failed turn
          return;
        }
        pending.innerHTML = result.data.answer_html || escapeText(result.data.answer);
        addSources(result.data.sources);
        messages.push({
          role: "assistant",
          content: result.data.answer,
          html: result.data.answer_html,
          sources: result.data.sources,
        });
        persistChat();
      })
      .catch(function () {
        pending.textContent = "Error: could not reach the server.";
        pending.classList.add("chat-message-error");
        messages.pop();
      })
      .finally(function () {
        input.disabled = false;
        input.focus();
      });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    const message = input.value.trim();
    if (!message) return;
    ask(message);
  });

  newChatBtn.addEventListener("click", startNewChat);

  // --- Entity links -> view panel ---

  function renderPreview(data) {
    viewPanel.innerHTML = "";

    const titleEl = document.createElement("h3");
    titleEl.className = "view-panel-title";
    titleEl.textContent = data.title;
    viewPanel.appendChild(titleEl);

    if (data.subtitle) {
      const subtitleEl = document.createElement("p");
      subtitleEl.className = "view-panel-subtitle";
      subtitleEl.textContent = data.subtitle;
      viewPanel.appendChild(subtitleEl);
    }

    const list = document.createElement("ul");
    list.className = "view-panel-facts";
    data.facts.forEach(function (f) {
      const li = document.createElement("li");
      if (f.derived) {
        const tag = document.createElement("span");
        tag.className = "tag tag-derived";
        tag.textContent = "derived ";
        li.appendChild(tag);
      }
      li.appendChild(document.createTextNode(f.text));
      list.appendChild(li);
    });
    viewPanel.appendChild(list);

    if (data.truncated) {
      const more = document.createElement("p");
      more.className = "view-panel-more";
      more.textContent = "More facts available on the full page.";
      viewPanel.appendChild(more);
    }

    const link = document.createElement("a");
    link.className = "view-panel-link";
    link.href = data.full_url;
    link.textContent = "Open full page →";
    viewPanel.appendChild(link);
  }

  log.addEventListener("click", function (e) {
    const link = e.target.closest(".entity-link");
    if (!link) return;
    e.preventDefault();
    const type = link.dataset.type;
    const id = link.dataset.id;
    viewPanel.innerHTML = '<p class="view-panel-empty">Loading...</p>';
    fetch("/api/preview/" + encodeURIComponent(type) + "/" + encodeURIComponent(id))
      .then(function (r) {
        if (!r.ok) throw new Error("not found");
        return r.json();
      })
      .then(renderPreview)
      .catch(function () {
        viewPanel.innerHTML = '<p class="view-panel-empty">Could not load details for this item.</p>';
      });
  });

  renderSidebar();
})();
