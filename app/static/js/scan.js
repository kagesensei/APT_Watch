(function () {
  const form = document.getElementById("scan-form");
  const fileInput = document.getElementById("scan-file");
  const status = document.getElementById("scan-status");
  const results = document.getElementById("scan-results");

  function renderResults(data) {
    results.innerHTML = "";
    status.textContent = `Found ${data.total_indicators_found} indicator(s) in the file.`;

    if (data.results.length === 0) return;

    const table = document.createElement("table");
    table.className = "data-table";
    table.innerHTML =
      "<thead><tr><th>Indicator</th><th>Type</th><th>Match</th><th>Detail</th></tr></thead>";
    const tbody = document.createElement("tbody");

    data.results.forEach(function (r) {
      const tr = document.createElement("tr");

      const indicatorTd = document.createElement("td");
      indicatorTd.textContent = r.indicator;
      tr.appendChild(indicatorTd);

      const typeTd = document.createElement("td");
      typeTd.textContent = r.type;
      tr.appendChild(typeTd);

      const matchTd = document.createElement("td");
      const tag = document.createElement("span");
      tag.className = "tag" + (r.matched ? " tag-derived" : "");
      tag.textContent = r.matched ? "MATCH" : "no match";
      matchTd.appendChild(tag);
      tr.appendChild(matchTd);

      const detailTd = document.createElement("td");
      if (r.facts.length > 0) {
        const list = document.createElement("ul");
        list.className = "pill-list";
        r.facts.forEach(function (f) {
          const li = document.createElement("li");
          if (f.derived) {
            const derivedTag = document.createElement("span");
            derivedTag.className = "tag tag-derived";
            derivedTag.textContent = "derived ";
            li.appendChild(derivedTag);
          }
          li.appendChild(document.createTextNode(f.text));
          list.appendChild(li);
        });
        detailTd.appendChild(list);
      } else {
        detailTd.textContent = "—";
      }
      tr.appendChild(detailTd);

      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    results.appendChild(table);
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    const file = fileInput.files[0];
    if (!file) return;

    status.textContent = "Scanning...";
    results.innerHTML = "";

    const formData = new FormData();
    formData.append("file", file);

    fetch("/scan/upload", { method: "POST", body: formData })
      .then(function (resp) {
        const contentType = resp.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
          throw new Error("Server returned an unexpected response (status " + resp.status + ").");
        }
        return resp.json().then(function (data) {
          return { ok: resp.ok, data: data };
        });
      })
      .then(function (result) {
        if (!result.ok) {
          status.textContent = "Error: " + (result.data.error || "something went wrong.");
          return;
        }
        renderResults(result.data);
      })
      .catch(function (err) {
        status.textContent = "Error: " + err.message;
      });
  });
})();
