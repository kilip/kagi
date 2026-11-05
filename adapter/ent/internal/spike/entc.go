//go:build ignore

package main

import (
	"log"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
	kagientc "github.com/kilip/kagi/adapter/ent/entc"
)

func main() {
	cfg := &gen.Config{
		Package: "github.com/kilip/kagi/adapter/ent/internal/spike/ent",
		Target:  "./ent",
	}
	err := entc.Generate("./schema", cfg, entc.Extensions(kagientc.NewExtension()))
	if err != nil {
		log.Fatalf("running ent codegen: %v", err)
	}
}
