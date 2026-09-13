(function () {
  const log = document.getElementById("chat-log");
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const history = [];
  const HISTORY_LIMIT = 6;

  function removeSuggestions() {
    const el = log.querySelector(".chat-suggestions");
    if (el) el.remove();
  }

  function addMessage(role, text) {
    const el = document.createElement("div");
    el.className = "chat-message chat-message-" + role;
    el.textContent = text;
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

  function ask(message) {
    removeSuggestions();
    addMessage("user", message);
    input.value = "";
    input.disabled = true;
    const pending = addMessage("assistant", "Thinking...");

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
          return;
        }
        pending.textContent = result.data.answer;
        addSources(result.data.sources);
        history.push(message);
        if (history.length > HISTORY_LIMIT) history.shift();
      })
      .catch(function () {
        pending.textContent = "Error: could not reach the server.";
        pending.classList.add("chat-message-error");
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

  log.querySelectorAll(".chat-suggestion").forEach(function (btn) {
    btn.addEventListener("click", function () {
      ask(btn.textContent);
    });
  });
})();
