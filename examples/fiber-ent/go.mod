module github.com/kilip/kagi/examples/fiber-ent

go 1.27

replace (
	github.com/kilip/kagi => ../..
	github.com/kilip/kagi/adapter/ent => ../../adapter/ent
	github.com/kilip/kagi/http/fiber => ../../http/fiber
)

require (
	entgo.io/ent v0.14.3
	github.com/gofiber/fiber/v2 v2.52.16
	github.com/kilip/kagi v0.0.0-00010101000000-000000000000
	github.com/kilip/kagi/adapter/ent v0.0.0-00010101000000-000000000000
	github.com/kilip/kagi/http/fiber v0.0.0-00010101000000-000000000000
	github.com/mattn/go-sqlite3 v1.14.24
)

require github.com/google/uuid v1.6.0 // indirect
