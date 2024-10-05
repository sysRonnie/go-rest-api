package auth

import (
	"context"
	"fmt"
	"go-rest-api/config"
	"go-rest-api/types"
	"go-rest-api/utils"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserKey contextKey = "userID"

func CreateJWT(secret []byte, userID int) (string, error) {
	expiration := time.Second * time.Duration(config.Envs.JWTExpirationInSeconds)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":    strconv.Itoa(userID),
		"expiredAt": time.Now().Add(expiration).Unix(),
	})

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func WithJWTAuth(handlerFunc http.HandlerFunc, store types.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := getTokenFromRequest(r)

		token, err := validateToken(tokenString)
		if err != nil {
			log.Printf("failed to validate token: %v", err)
			permissionDenied(w)
			return
		}

		if !token.Valid {
			log.Println("invalid token")
			permissionDenied(w)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["userID"] == nil {
			log.Println("invalid claims in token")
			permissionDenied(w)
			return
		}

		userIDStr, ok := claims["userID"].(string)
		if !ok || userIDStr == "" {
			log.Println("invalid userID in token claims")
			permissionDenied(w)
			return
		}

		userID, err := strconv.Atoi(userIDStr)
		if err != nil {
			log.Printf("failed to parse userID: %v", err)
			permissionDenied(w)
			return
		}

		u, err := store.GetUserByID(userID)
		if err != nil {
			log.Printf("failed to get user by id: %v", err)
			permissionDenied(w)
			return
		}

		ctx := r.Context()
		ctx = context.WithValue(ctx, UserKey, u.ID)
		r = r.WithContext(ctx)

		handlerFunc(w, r)
	}
}

func getTokenFromRequest(r *http.Request) string {
	tokenAuth := r.Header.Get("Authorization")
	if tokenAuth == "" || len(strings.Split(tokenAuth, ".")) != 3 {
		return ""
	}
	return tokenAuth
}

func validateToken(t string) (*jwt.Token, error) {
	if t == "" {
		return nil, fmt.Errorf("token is empty or invalid")
	}

	token, err := jwt.Parse(t, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(config.Envs.JWTSecret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}
	return token, nil
}

func permissionDenied(w http.ResponseWriter) {
	utils.WriteError(w, http.StatusForbidden, fmt.Errorf("Permission Denied."))
}

func GetUserIDFromContext(ctx context.Context) int {
	userID, ok := ctx.Value(UserKey).(int)

	if !ok {
		return -1
	}

	return userID
}
