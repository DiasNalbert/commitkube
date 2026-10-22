package middleware

import (
	"log"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

var JWTSecret = func() []byte {
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		log.Fatal("JWT_SECRET environment variable is required")
	}
	return []byte(s)
}()

// AccessTokenType marks the one kind of token that is a sign-in. Everything
// else signed with JWTSecret -- the stage tickets handed out between the
// password and the MFA code -- carries a user_id too, and was accepted here as
// though it were a session: a password alone was enough to call the API as
// that person. The check is on what a token says it is, not on what it lacks,
// so a token type added later is refused until someone decides otherwise.
const AccessTokenType = "access"

func AuthRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		tokenString := ""
		authHeader := c.Get("Authorization")
		if authHeader != "" {
			parts := strings.Split(authHeader, " ")
			if len(parts) == 2 && parts[0] == "Bearer" {
				tokenString = parts[1]
			}
		}
		// The header is the only place a session is read from. A token in
		// the query string ends up in proxy access logs, browser history
		// and Referer headers -- nginx here logs every URL to stdout -- and
		// nothing in the frontend needs it: the log stream uses fetch so it
		// can send this header.
		if tokenString == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing authorization token"})
		}
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.ErrUnauthorized
			}
			return JWTSecret, nil
		})

		if err != nil || !token.Valid {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired token"})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || claims["typ"] != AccessTokenType {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
		}

		c.Locals("user_id", claims["user_id"])
		c.Locals("role", claims["role"])
		if sid, ok := claims["sid"].(string); ok {
			c.Locals("session_id", sid)
		}
		return c.Next()
	}
}
