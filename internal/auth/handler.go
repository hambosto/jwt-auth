package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) Register(ctx *gin.Context) {
	var input RegisterInput
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.Register(input); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register user"})
		return
	}
	ctx.JSON(http.StatusCreated, gin.H{"message": "user registered successfully"})
}

func (h *Handler) Login(ctx *gin.Context) {
	var input LoginInput
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := h.service.Login(input)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"token": token})
}

func (h *Handler) ForgotPassword(ctx *gin.Context) {
	var input ForgotPasswordInput
	if err := ctx.ShouldBindBodyWithJSON(&input); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.service.ForgotPassword(input); err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to proccess forgot password request"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"message": "if a user with that email exists, a password reset email will be sent"})
}

func (h *Handler) GetProfile(ctx *gin.Context) {
	userID, exists := ctx.Get("user_id")
	if !exists {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	userService := ctx.MustGet("user_service").(UserService)

	// Cast userID to uint (ensure your middleware provides it as uint)
	user, err := userService.GetUserByID(userID.(uint))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve user information"})
		return
	}

	if user == nil {
		ctx.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"message": "User profile fetched successfully",
		"user":    user,
	})
}
