// internal/routes/routes.go
package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/hambosto/jwt-auth/internal/auth"
	"github.com/hambosto/jwt-auth/internal/middleware"
)

func SetupRoutes(r *gin.Engine, authHandler *auth.Handler, userService *auth.Service, jwtSecret string) {
	// Store the user service in the context
	r.Use(func(c *gin.Context) {
		c.Set("user_id", userService)
		c.Next()
	})

	// Public routes
	r.POST("/auth/register", authHandler.Register)
	r.POST("/auth/login", authHandler.Login)
	r.POST("/auth/forgot-password", authHandler.ForgotPassword)

	// Protected routes
	api := r.Group("/api")
	api.Use(middleware.AuthMiddleWare(jwtSecret))
	{
		api.GET("/profile", authHandler.GetProfile)
	}
}
