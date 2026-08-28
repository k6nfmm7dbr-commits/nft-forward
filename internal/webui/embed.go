// Package webui 内嵌前端静态资源（HTML/CSS/JS）。
package webui

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticFS embed.FS

// FS 返回 static 子目录的文件系统。
func FS() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
