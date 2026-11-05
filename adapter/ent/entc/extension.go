package entc

import (
	"embed"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

//go:embed templates/*
var templateFS embed.FS

// Extension implements entc.Extension for generating Kagi adapters.
type Extension struct {
	entc.DefaultExtension
}

// Option allows customizing the extension.
type Option func(*Extension)

// NewExtension returns a new Kagi entc extension.
func NewExtension(opts ...Option) *Extension {
	ex := &Extension{}
	for _, opt := range opts {
		opt(ex)
	}
	return ex
}

// Templates returns the templates provided by the extension.
func (e *Extension) Templates() []*gen.Template {
	tmpl := gen.MustParse(gen.NewTemplate("kagi_user_store").
		ParseFS(templateFS, "templates/kagi_user_store.tmpl"))
	return []*gen.Template{tmpl}
}
