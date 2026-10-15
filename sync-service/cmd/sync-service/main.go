package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/httpapi"
	"github.com/yexiaoye-blue/CitriPass/sync-service/internal/pgstore"
)

func main() {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	store, err := pgstore.Open(context.Background(), databaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()
	server := &http.Server{
		Addr:    addr,
		Handler: httpapi.Handler(store),
	}
	log.Printf("sync service listening on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
