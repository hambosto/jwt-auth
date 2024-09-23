package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/hambosto/jwt-auth/internal/auth"
	"github.com/hambosto/jwt-auth/internal/config"
	"github.com/hambosto/jwt-auth/internal/database"
	"github.com/hambosto/jwt-auth/internal/routes"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize databse
	db, err := database.InitDB(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Initialize auth service
	authService := auth.NewService(db, cfg.JWTSecret)

	// Initialize auth handler
	authHandler := auth.NewHandler(authService)

	// Set up Gin router
	r := gin.Default()

	// Set up routes
	routes.SetupRoutes(r, authHandler, authService, cfg.JWTSecret)

	// Start the server
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
