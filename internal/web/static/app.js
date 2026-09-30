/**
 * traefik-authz admin panel.
 *
 * Loads the whole state from GET /api/state and renders three sections:
 * pending access requests (approve or dismiss), users (add, grant apps with
 * toggles, disable, delete) and the apps found by discovery. Every change is
 * one JSON call that carries the X-Requested-With header the server demands,
 * followed by a reload of the state.
 */

const app = document.getElementById("app");
const statusDot = document.querySelector(".status__dot");
const statusText = document.getElementById("status-text");
const toast = document.getElementById("toast");
const confirmDialog = document.getElementById("confirm");

let state = { me: "", admins: [], users: [], apps: [], requests: [] };
let toastTimer = 0;

function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "class") el.className = value;
    else if (key in el && typeof value !== "string") el[key] = value;
    else el.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

async function api(method, path, body) {
  const init = { method, credentials: "include", headers: { "X-Requested-With": "traefik-authz" } };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(`api/${path}`, init);
  } catch {
    throw new Error("Server unreachable or signed out: reload the page");
  }
  if (response.redirected || response.type === "opaqueredirect") throw new Error("Signed out: reload to sign in again");
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    if (!response.ok) throw new Error(response.status === 403 ? "Admins only" : `HTTP ${response.status}`);
    throw new Error("Unexpected response: reload to sign in again");
  }
  if (!response.ok) throw new Error(data?.error || `HTTP ${response.status}`);
  return data;
}

function showToast(message) {
  toast.textContent = message;
  toast.setAttribute("data-show", "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.removeAttribute("data-show"), 3200);
}

function setStatus(kind, text) {
  statusDot.dataset.state = kind;
  statusText.textContent = text;
}

function relative(iso) {
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  const units = [
    ["d", 86400],
    ["h", 3600],
    ["min", 60],
  ];
  for (const [unit, size] of units) {
    if (seconds >= size) return `${Math.floor(seconds / size)} ${unit} ago`;
  }
  return "just now";
}

function appByHost(host) {
  return state.apps.find((a) => a.host === host);
}

function icon(appInfo) {
  const glyph = Array.from((appInfo?.icon || "").trim()).slice(0, 2).join("") || (appInfo?.name || "?").slice(0, 1).toUpperCase();
  return h("span", { class: "card__icon", "aria-hidden": "true" }, glyph);
}

async function act(button, work, done) {
  const buttons = button ? [button] : [];
  buttons.forEach((b) => (b.disabled = true));
  document.body.setAttribute("data-loading", "");
  try {
    await work();
    if (done) showToast(done);
    await load();
  } catch (error) {
    showToast(error.message);
    await load();
  } finally {
    buttons.forEach((b) => (b.disabled = false));
    document.body.removeAttribute("data-loading");
  }
}

function confirmAction(title, text, okLabel) {
  document.getElementById("confirm-title").textContent = title;
  document.getElementById("confirm-text").textContent = text;
  document.getElementById("confirm-ok").textContent = okLabel;
  confirmDialog.returnValue = "";
  confirmDialog.showModal();
  return new Promise((resolve) => {
    confirmDialog.addEventListener("close", () => resolve(confirmDialog.returnValue === "ok"), { once: true });
  });
}

function section(id, title, count, ...body) {
  return h(
    "section",
    { class: "project", id, "aria-labelledby": `${id}-title` },
    h("div", { class: "project__head" }, h("h2", { class: "project__title", id: `${id}-title` }, title), h("span", { class: "project__count" }, count)),
    ...body
  );
}

function empty(title, hint) {
  return h("div", { class: "empty" }, h("div", { class: "empty__glyph", "aria-hidden": "true" }), h("p", { class: "empty__title" }, title), h("p", { class: "empty__hint" }, hint));
}

function requestCard(request) {
  const target = appByHost(request.host);
  const requester = state.users.find((u) => u.email === request.email);
  const approve = h("button", { class: "btn btn--primary btn--small", type: "button" }, "Approve");
  const dismiss = h("button", { class: "btn btn--small", type: "button" }, "Dismiss");
  const key = { email: request.email, host: request.host };
  approve.addEventListener("click", () => act(approve, () => api("POST", "requests/approve", key), `Granted ${target?.name || request.host} to ${request.email}`));
  dismiss.addEventListener("click", () => act(dismiss, () => api("POST", "requests/dismiss", key), "Request dismissed"));
  return h(
    "article",
    { class: "card card--nolink" },
    h("div", { class: "card__head" }, icon(target), h("span", { class: "card__title", title: request.email }, request.email)),
    h("p", { class: "card__desc" }, `wants ${target?.name || request.host}`),
    h(
      "div",
      { class: "card__meta" },
      h("span", { class: "chip" }, request.host),
      h("span", { class: "chip" }, relative(request.requested_at)),
      requester?.disabled && h("span", { class: "chip chip--warn" }, "user disabled")
    ),
    h("div", { class: "card__actions" }, dismiss, approve)
  );
}

function userCard(user) {
  const granted = new Set(user.app_ids);
  const toggles = state.apps.map((a) => {
    const input = h("input", { type: "checkbox", checked: granted.has(a.id) });
    input.addEventListener("change", () => {
      const path = `users/${encodeURIComponent(user.email)}/apps/${a.id}`;
      act(null, () => api(input.checked ? "PUT" : "DELETE", path), `${input.checked ? "Granted" : "Revoked"} ${a.name} for ${user.email}`);
      input.disabled = true;
    });
    return h("label", { class: "toggles__option", title: a.host }, input, h("span", {}, a.name));
  });
  const toggle = h("button", { class: "btn btn--small", type: "button" }, user.disabled ? "Enable" : "Disable");
  toggle.addEventListener("click", () =>
    act(toggle, () => api("PATCH", `users/${encodeURIComponent(user.email)}`, { disabled: !user.disabled }), `${user.email} ${user.disabled ? "enabled" : "disabled"}`)
  );
  const remove = h("button", { class: "btn btn--danger btn--small", type: "button" }, "Delete");
  remove.addEventListener("click", async () => {
    const ok = await confirmAction(`Delete ${user.email}?`, "The user and every grant it holds are removed. Access requests it makes later show up again.", "Delete");
    if (ok) act(remove, () => api("DELETE", `users/${encodeURIComponent(user.email)}`), `${user.email} deleted`);
  });
  return h(
    "article",
    { class: `card card--nolink${user.disabled ? " card--muted" : ""}` },
    h("div", { class: "card__head" }, h("span", { class: "card__title", title: user.email }, user.email), user.disabled && h("span", { class: "chip chip--warn" }, "disabled")),
    user.name && h("p", { class: "card__desc" }, user.name),
    toggles.length
      ? h("fieldset", { class: "toggles" }, h("legend", { class: "card__mono" }, "Apps"), toggles)
      : h("p", { class: "card__desc" }, "No apps discovered yet."),
    h("div", { class: "card__actions" }, toggle, remove)
  );
}

function adder() {
  const email = h("input", { class: "field field--mono", type: "email", name: "email", placeholder: "user@example.com", required: true, autocomplete: "off", "aria-label": "E-mail address" });
  const name = h("input", { class: "field", type: "text", name: "name", placeholder: "Name (optional)", autocomplete: "off", "aria-label": "Name" });
  const submit = h("button", { class: "btn btn--primary", type: "submit" }, "Add user");
  const form = h("form", { class: "adder" }, email, name, submit);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    act(
      submit,
      async () => {
        await api("POST", "users", { email: email.value, name: name.value });
        form.reset();
      },
      `${email.value.trim().toLowerCase()} added`
    );
  });
  return form;
}

function appCard(a) {
  return h(
    "article",
    { class: "card card--nolink" },
    h("div", { class: "card__head" }, icon(a), h("span", { class: "card__title card__title--sans" }, a.name)),
    h("span", { class: "card__mono" }, a.host),
    h("div", { class: "card__meta" }, h("span", { class: "chip" }, `router ${a.router}`), h("span", { class: "chip" }, `seen ${relative(a.last_seen)}`))
  );
}

const adderForm = adder();

function render() {
  const admins = h("p", { class: "project__note" }, "Admins reach every app and this panel: ", state.admins.map((a, i) => [i ? ", " : "", h("code", {}, a)]));
  app.replaceChildren(
    section(
      "requests",
      "Access requests",
      state.requests.length,
      state.requests.length ? h("div", { class: "grid" }, state.requests.map(requestCard)) : empty("No pending requests", "Denied visits to a known app show up here.")
    ),
    section("users", "Users", state.users.length, admins, adderForm, state.users.length ? h("div", { class: "grid" }, state.users.map(userCard)) : empty("No users yet", "Add one above, or approve a request.")),
    section(
      "apps",
      "Apps",
      state.apps.length,
      state.apps.length ? h("div", { class: "grid" }, state.apps.map(appCard)) : empty("No apps discovered", "Add the traefik-authz middleware to a router's labels.")
    )
  );
}

async function load() {
  try {
    const next = await api("GET", "state");
    state = next;
    render();
    setStatus("live", state.me);
  } catch (error) {
    setStatus("error", error.message);
  } finally {
    document.body.removeAttribute("data-loading");
  }
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") load();
});

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}

load();
