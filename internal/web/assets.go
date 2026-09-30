package web

import "embed"

// Static is the admin PWA: the page, its styles and script, the web app
// manifest, the service worker and the icons, served under /.
//
//go:embed static
var Static embed.FS
