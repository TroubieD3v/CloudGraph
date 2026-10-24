The web UI build (`npm --prefix web run build`) is written to `app/` in this
directory and embedded into the binary. This file keeps the directory present
so the Go code compiles without a UI build.
