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
	userTmpl := gen.MustParse(gen.NewTemplate("kagi_user_store").
		ParseFS(templateFS, "templates/kagi_user_store.tmpl"))
	accountTmpl := gen.MustParse(gen.NewTemplate("kagi_account_store").
		ParseFS(templateFS, "templates/kagi_account_store.tmpl"))
	sessionTmpl := gen.MustParse(gen.NewTemplate("kagi_session_store").
		ParseFS(templateFS, "templates/kagi_session_store.tmpl"))
	verificationTmpl := gen.MustParse(gen.NewTemplate("kagi_verification_store").
		ParseFS(templateFS, "templates/kagi_verification_store.tmpl"))
	rateLimitTmpl := gen.MustParse(gen.NewTemplate("kagi_rate_limit_store").
		ParseFS(templateFS, "templates/kagi_rate_limit_store.tmpl"))
	adapterTmpl := gen.MustParse(gen.NewTemplate("kagi_adapter").
		ParseFS(templateFS, "templates/kagi_adapter.tmpl"))
	return []*gen.Template{userTmpl, accountTmpl, sessionTmpl, verificationTmpl, rateLimitTmpl, adapterTmpl}
}
