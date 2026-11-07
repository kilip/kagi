package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gofiber/fiber/v2"
	_ "github.com/mattn/go-sqlite3"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/examples/fiber-ent/ent"
	fiberpkg "github.com/kilip/kagi/http/fiber"
)

// Config holds runtime configuration for the example application.
type Config struct {
	DatabaseURL string
	Secret      string
	Port        string
}

// SetupApp initializes database connection, runs migrations, configures Kagi, and registers Fiber routes.
func SetupApp(cfg Config) (*fiber.App, *ent.Client, *kagi.Kagi, error) {
	client, err := ent.Open("sqlite3", cfg.DatabaseURL)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed opening connection to sqlite: %w", err)
	}

	if err := client.Schema.Create(context.Background()); err != nil {
		_ = client.Close()
		return nil, nil, nil, fmt.Errorf("failed creating schema resources: %w", err)
	}

	adapter := ent.NewKagiAdapter(client)

	auth, err := kagi.New(kagi.Config{
		UserStore:         adapter.User,
		AccountStore:      adapter.Account,
		SessionStore:      adapter.Session,
		VerificationStore: adapter.Verification,
		RateLimitStore:    adapter.RateLimit,
		SecondaryStorage:  nil, // Works completely without Redis
		Secret:            cfg.Secret,
	})
	if err != nil {
		_ = client.Close()
		return nil, nil, nil, fmt.Errorf("failed initializing kagi: %w", err)
	}

	app := fiber.New()

	h := fiberpkg.Register(app, auth, fiberpkg.WithPrefix("/auth"), fiberpkg.WithInsecureDevMode(true))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "ok",
			"message": "Kagi Fiber+Ent Example",
		})
	})

	app.Get("/me", h.RequireAuth(fiberpkg.WithMiddlewareFetchUser(true)), func(c *fiber.Ctx) error {
		user := fiberpkg.UserFromCtx(c)
		session := fiberpkg.SessionFromCtx(c)
		return c.JSON(fiber.Map{
			"user":    user,
			"session": session,
		})
	})

	return app, client, auth, nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func main() {
	cfg := Config{
		DatabaseURL: getEnv("DATABASE_URL", "file:kagi_example.db?cache=shared&_fk=1"),
		Secret:      getEnv("KAGI_SECRET", "dev-secret-key-must-be-at-least-32-bytes-long!"),
		Port:        getEnv("PORT", "3000"),
	}

	app, client, _, err := SetupApp(cfg)
	if err != nil {
		log.Fatalf("failed to setup app: %v", err)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	serverShutdown := make(chan struct{})
	go func() {
		<-quit
		log.Println("Shutting down server...")

		if err := app.Shutdown(); err != nil {
			log.Printf("error shutting down fiber app: %v", err)
		}
		if err := client.Close(); err != nil {
			log.Printf("error closing ent client: %v", err)
		}
		close(serverShutdown)
	}()

	addr := cfg.Port
	if !strings.HasPrefix(addr, ":") {
		addr = ":" + addr
	}

	log.Printf("Server listening on %s", addr)
	if err := app.Listen(addr); err != nil {
		log.Printf("server error: %v", err)
		_ = client.Close()
		return
	}

	<-serverShutdown
}
