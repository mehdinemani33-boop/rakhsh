package panel

import "embed"

//go:embed web
var webFiles embed.FS

func init() { WebFS = webFiles }
