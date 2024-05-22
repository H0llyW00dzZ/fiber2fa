// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa

import (
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/gofiber/storage/memory/v2"
	"github.com/xlzd/gotp"
)

// Middleware represents the 2FA middleware.
type Middleware struct {
	Config *Config
}

// New creates a new instance of the 2FA middleware with the provided configuration.
func New(config ...Config) fiber.Handler {
	cfg := defaultConfig

	if len(config) > 0 {
		cfg = config[0]
	}

	// Directly create the storage inside the middleware if not provided.
	if cfg.Storage == nil {
		cfg.Storage = memory.New()
	}

	m := &Middleware{
		Config: &cfg, // Store a pointer to the config
	}

	// Return the handle method bound to the Middleware instance.
	return m.Handle
}

// Handle is the method on Middleware that handles the 2FA authentication process.
func (m *Middleware) Handle(c *fiber.Ctx) error {
	// Check if the middleware should be skipped
	if m.Config.Next != nil && m.Config.Next(c) {
		return c.Next()
	}

	// Check if the requested path is in the skip list
	if m.isPathSkipped(c.Path()) {
		return c.Next()
	}

	contextKey, err := m.getContextKey(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString(err.Error())
	}

	// Check if the user has a valid 2FA cookie
	if m.isValidCookie(c) {
		return c.Next()
	}

	info, err := m.getInfoFromStorage(contextKey)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	// Check if info was found in the storage
	if info == nil {
		// No info found, user probably not registered for 2FA
		return c.Status(fiber.StatusUnauthorized).SendString("2FA information not found")
	}

	// Extract the token from the specified token lookup sources
	token := m.extractToken(c)
	if token == "" {
		// No token provided, redirecting to 2FA page.
		return c.Redirect(m.Config.RedirectURL, fiber.StatusFound)
	}
	// Verify the provided token
	if !m.verifyToken(info, token) {
		// Token is invalid, sending unauthorized response.
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid 2FA token")
	}

	if err := m.setCookie(c, info); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	// Store the updated Info struct in the storage
	if err := m.updateInfoInStorage(contextKey, info); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}

	return c.Next()
}

// isPathSkipped checks if the given path is in the skip list.
func (m *Middleware) isPathSkipped(path string) bool {
	for _, skippedPath := range m.Config.SkipCookies {
		if path == skippedPath {
			return true
		}
	}
	return false
}

// getContextKey retrieves the context key from c.Locals using the provided ContextKey.
func (m *Middleware) getContextKey(c *fiber.Ctx) (string, error) {
	if m.Config.ContextKey == "" {
		return "", fmt.Errorf("ContextKey is not set")
	}

	contextKeyValue, ok := c.Locals(m.Config.ContextKey).(string)
	if !ok {
		return "", fmt.Errorf("failed to retrieve context key")
	}

	return contextKeyValue, nil
}

// isValidCookie checks if the user has a valid 2FA cookie.
func (m *Middleware) isValidCookie(c *fiber.Ctx) bool {
	cookie := c.Cookies(m.Config.CookieName)
	if cookie == "" {
		return false
	}

	return m.validateCookie(cookie)
}

// setCookie sets the 2FA cookie with an expiration time.
//
// Note: This is suitable for use with encrypted cookies Fiber.
func (m *Middleware) setCookie(c *fiber.Ctx, info *Info) error {
	expirationTime := time.Now().Add(time.Duration(m.Config.CookieMaxAge) * time.Second)
	cookieValue := m.GenerateCookieValue(expirationTime)

	// Set the cookie domain dynamically based on the request's domain if HTTPS is used
	cookieDomain := m.Config.CookieDomain
	secure := m.Config.CookieSecure
	if cookieDomain == "auto" && c.Secure() {
		cookieDomain = utils.CopyString(c.Hostname())
		secure = true
	}

	c.Cookie(&fiber.Cookie{
		Name:     m.Config.CookieName,
		Value:    cookieValue,
		Expires:  expirationTime,
		Path:     m.Config.CookiePath,
		Domain:   cookieDomain,
		Secure:   secure,
		HTTPOnly: true,
	})

	info.SetCookieValue(cookieValue)
	info.SetExpirationTime(expirationTime)

	return nil
}

// extractToken extracts the token from the specified token lookup sources.
func (m *Middleware) extractToken(c *fiber.Ctx) string {
	tokenLookup := m.Config.TokenLookup

	sources := strings.Split(tokenLookup, ",")
	for _, source := range sources {
		parts := strings.Split(source, ":")
		if len(parts) != 2 {
			continue
		}

		sourceType := parts[0]
		key := parts[1]

		switch sourceType {
		case "query":
			token := c.Query(key)
			if token != "" {
				return utils.CopyString(token)
			}
		case "form":
			token := c.FormValue(key)
			if token != "" {
				return utils.CopyString(token)
			}
		case "cookie":
			token := c.Cookies(key)
			if token != "" {
				return utils.CopyString(token)
			}
		case "header":
			token := c.Get(key)
			if strings.HasPrefix(token, "Bearer ") {
				return utils.CopyString(strings.TrimPrefix(token, "Bearer "))
			}
		case "param":
			token := c.Params(key)
			if token != "" {
				return utils.CopyString(token)
			}
		}
	}

	return ""
}

// verifyToken verifies the provided token against the user's secret.
func (m *Middleware) verifyToken(info *Info, token string) bool {
	totp := gotp.NewDefaultTOTP(info.GetSecret())
	return totp.Verify(token, time.Now().Unix())
}
