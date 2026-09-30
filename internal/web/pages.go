package web

import (
	"html/template"
	"net/http"

	"traefik-authz/internal/authz"
)

type page struct {
	Title  string
	Detail string
	Email  string
}

var forbiddenPage = template.Must(template.New("forbidden").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="robots" content="noindex">
<title>{{.Title}}</title>
<style>
:root{color-scheme:dark;--font-sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;--font-mono:ui-monospace,"SF Mono","JetBrains Mono","Cascadia Code",Menlo,Consolas,monospace;--bg:#0b0d10;--surface-1:#131720;--border:rgba(255,255,255,.07);--text:#e7e9ee;--text-muted:#9aa1ad;--accent-weak:rgba(123,131,245,.14);--danger:#ed6a63;--danger-weak:rgba(237,106,99,.16);--r-card:14px}
@media (prefers-color-scheme:light){:root{color-scheme:light;--bg:#f6f7f9;--surface-1:#fff;--border:rgba(17,20,28,.09);--text:#171a21;--text-muted:#5c6472;--accent-weak:rgba(85,96,230,.12);--danger:#d1453f;--danger-weak:rgba(209,69,63,.12)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:1.5rem;background:radial-gradient(1200px 520px at 50% -12%,var(--accent-weak),transparent 62%),var(--bg);color:var(--text);font-family:var(--font-sans);font-size:.9375rem;line-height:1.55;-webkit-font-smoothing:antialiased}
.card{max-width:420px;width:100%;padding:1.6rem 1.5rem;background:var(--surface-1);border:1px solid var(--border);border-radius:var(--r-card);display:flex;flex-direction:column;gap:.7rem}
.chip{align-self:flex-start;font-size:.72rem;font-weight:600;color:var(--danger);background:var(--danger-weak);border-radius:999px;padding:.12rem .55rem}
h1{margin:0;font-size:1.2rem;font-weight:600;letter-spacing:-.015em}
p{margin:0;color:var(--text-muted);font-size:.88rem}
code{font-family:var(--font-mono);font-size:.82rem;color:var(--text)}
</style>
</head>
<body>
<main class="card">
<span class="chip">403</span>
<h1>{{.Title}}</h1>
<p>{{.Detail}}</p>
{{if .Email}}<p>Signed in as <code>{{.Email}}</code>.</p>{{end}}
</main>
</body>
</html>
`))

func deniedPage(d authz.Decision) page {
	switch d.Reason {
	case authz.NoUser:
		return page{Title: "Not signed in", Detail: "This site expects a sign-in in front of it, and none took place."}
	case authz.UnknownHost:
		return page{Title: "Access denied", Detail: "This site is not open to anyone yet.", Email: d.Email}
	case authz.Disabled:
		return page{Title: "Account disabled", Detail: "Your account has been disabled. Ask an administrator to turn it back on.", Email: d.Email}
	default:
		return page{Title: "You don't have access to " + d.App.Name, Detail: "Your request has been recorded; an administrator can grant it from the panel.", Email: d.Email}
	}
}

func panelDeniedPage(email string) page {
	if email == "" {
		return page{Title: "Not signed in", Detail: "The admin panel expects a sign-in in front of it, and none took place."}
	}
	return page{Title: "Admins only", Detail: "Only administrators can open this panel.", Email: email}
}

func writeForbidden(w http.ResponseWriter, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	forbiddenPage.Execute(w, p)
}
