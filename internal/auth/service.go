package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Service struct {
	db          *gorm.DB
	jwtSecret   string
	tokenExpiry time.Duration
}

type UserService interface {
	GetUserByID(userID uint) (*User, error)
}

func NewService(db *gorm.DB, jwtSecret string) *Service {
	return &Service{
		db:          db,
		jwtSecret:   jwtSecret,
		tokenExpiry: time.Hour * 24, // 24 hours
	}
}

func (s *Service) Register(input RegisterInput) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := User{
		Username: input.Username,
		Email:    input.Email,
		Password: string(hashedPassword),
	}

	result := s.db.Create(&user)
	return result.Error
}

func (s *Service) Login(input LoginInput) (string, error) {
	var user User
	if err := s.db.Where("email = ?", input.Email).First(&user).Error; err != nil {
		return "", errors.New("invalid email or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return "", errors.New("invalid email or password")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(s.tokenExpiry).Unix(),
	})

	tokenString, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (s *Service) ForgotPassword(input ForgotPasswordInput) error {
	var user User
	if err := s.db.Where("email = ?", input.Email).First(&user).Error; err != nil {
		return errors.New("user not found")
	}

	// Here you would typically generate a password reset token and send an email
	// For this example, we'll just print a message
	// In a real application, you'd want to implement proper email sending logic
	// and store the reset token in the database with an expiration time
	println("Password reset requested for:", user.Email)
	println("In a real application, an email would be sent with reset instructions")

	return nil
}

func (s *Service) GetUserByID(userID uint) (*User, error) {
	var user User
	if err := s.db.First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}
