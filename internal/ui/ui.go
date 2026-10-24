// Package ui embeds the compiled web interface.
package ui

import (
	"embed"
	"io/fs"
)

// dist always contains README.md, so the package builds even when the UI has
// not been built; the Vite output lives in dist/app.
//
//go:embed all:dist
var dist embed.FS

// FS returns the built UI rooted at index.html. Without a UI build it is
// empty and the server answers with a "UI not built" message.
func FS() fs.FS {
	sub, err := fs.Sub(dist, "dist/app")
	if err != nil {
		panic(err)
	}
	return sub
}
