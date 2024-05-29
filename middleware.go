// Copyright (c) 2024 H0llyW00dz All rights reserved.
//
// License: BSD 3-Clause License

package twofa

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	otp "github.com/H0llyW00dzZ/fiber2fa/internal/otpverifier"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	"github.com/gofiber/storage/memory/v2"
)

// Middleware represents the 2FA middleware.
type Middleware struct {
	Config       *Config
	Info         InfoManager
	PathHandlers []PathHandler
}

// PathHandler represents a path handler for the 2FA middleware.
type PathHandler struct {
	// Path is the URL path to match for the handler.
	Path string

	// Handler is the fiber.Handler function to be executed when the path matches.
	Handler fiber.Handler
}

// New creates a new instance of the 2FA middleware with the provided configuration.
func New(config ...Config) fiber.Handler {
	cfg := DefaultConfig

	if len(config) > 0 {
		cfg = config[0]
	}

	// Set default values for JSONMarshal and JSONUnmarshal if not provided
	if cfg.JSONMarshal == nil {
		cfg.JSONMarshal = json.Marshal
	}
	if cfg.JSONUnmarshal == nil {
		cfg.JSONUnmarshal = json.Unmarshal
	}

	// Directly create the storage inside the middleware if not provided.
	if cfg.Storage == nil {
		cfg.Storage = memory.New()
	}

	info := NewInfo(&cfg)

	m := &Middleware{
		Config: &cfg, // Store a pointer to the config
		Info:   info,
	}

	m.PathHandlers = []PathHandler{
		{
			Path:    m.Config.QRCode.PathTemplate,
			Handler: m.GenerateQRcodePath,
		},
	}

	// Return the handle method bound to the Middleware instance.
	return m.Handle
}

// Handle is the method on Middleware that handles the 2FA authentication process.
func (m *Middleware) Handle(c *fiber.Ctx) error {
	// Check if the middleware should be skipped
	if m.shouldSkipMiddleware(c) {
		return c.Next()
	}

	// Get the context key
	contextKey, err := m.getContextKey(c)
	if err != nil {
		return m.SendInternalErrorResponse(c, err)
	}

	// Get the 2FA information from storage
	info, err := m.getInfoFromStorage(contextKey)
	if err != nil {
		return m.SendInternalErrorResponse(c, ErrorFailedToRetrieveInfo)
	}

	// Check if 2FA information was found in the storage
	if info == nil {
		// No 2FA information found, handle missing information.
		return m.handleMissingInfo(c)
	}

	// Set the Info field of the Middleware struct
	m.Info = info

	// Check if the user has a valid 2FA cookie
	if m.isValidCookie(c) {
		return c.Next()
	}

	// Find the matching path handler
	for _, handler := range m.PathHandlers {
		if c.Path() == handler.Path {
			return handler.Handler(c)
		}
	}

	// Handle token verification and further processing
	return m.handleTokenVerification(c, contextKey)
}

// shouldSkipMiddleware checks if the middleware should be skipped based on the configuration.
func (m *Middleware) shouldSkipMiddleware(c *fiber.Ctx) bool {
	// Check if the middleware should be skipped using the Next function
	if m.Config.Next != nil && m.Config.Next(c) {
		return true
	}

	// Check if the requested path is in the skip list
	if m.isPathSkipped(c.Path()) {
		return true
	}

	return false
}

// handleMissingInfo handles the case when 2FA information is missing.
func (m *Middleware) handleMissingInfo(c *fiber.Ctx) error {
	// TODO: Handle missing 2FA mechanism.
	// This should be the place where "/2fa/register?account=%s" is in the wild (handled) instead of returning Unauthorized.
	return m.SendUnauthorizedResponse(c, fiber.NewError(fiber.StatusUnauthorized, "2FA information not found"))
}

// handleTokenVerification handles the token verification process and further processing.
func (m *Middleware) handleTokenVerification(c *fiber.Ctx, contextKey string) error {

	// Extract the token from the specified token lookup sources
	token := m.extractToken(c)
	if token == "" {
		// No token provided, redirecting to 2FA page.
		return c.Redirect(m.Config.RedirectURL, fiber.StatusFound)
	}

	// Verify the provided token and get the updated Info struct
	if !m.verifyToken(token) {
		// Token is invalid, sending unauthorized response.
		return m.SendUnauthorizedResponse(c, fiber.NewError(fiber.StatusUnauthorized, "Invalid 2FA token"))
	}

	// Check if the requested path is in the skip list
	if !m.isPathSkipped(c.Path()) {
		if err := m.setCookie(c); err != nil {
			return m.SendInternalErrorResponse(c, ErrorFailedToStoreInfo)
		}
	}

	// Store the updated Info struct in the storage
	if err := m.updateInfoInStorage(contextKey); err != nil {
		return m.SendInternalErrorResponse(c, ErrorFailedToStoreInfo)
	}

	return c.Next()
}

// isPathSkipped checks if the given path is in the skip list.
func (m *Middleware) isPathSkipped(path string) bool {
	// Note: No need to explicitly check for nil, you poggers.
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
		return "", ErrorContextKeyNotSet
	}

	contextKeyValue := c.Locals(m.Config.ContextKey)
	if contextKeyValue == nil {
		return "", ErrorContextKeyNotSet
	}

	contextKey, ok := contextKeyValue.(string)
	if !ok {
		return "", ErrorFailedToRetrieveContextKey
	}

	return contextKey, nil
}

// isValidCookie checks if the user has a valid 2FA cookie.
func (m *Middleware) isValidCookie(c *fiber.Ctx) bool {
	// Check if the middleware should be skipped
	// Note: No need to explicitly check for boolean by adding if-else statement, you poggers.
	m.shouldSkipMiddleware(c)

	cookie := c.Cookies(m.Config.CookieName)
	if cookie == "" {
		return false
	}

	if !m.validateCookie(cookie) {
		// Cookie is no longer valid, delete the Info struct from the storage using the ContextKey from the Info struct
		contextKeyValue := m.Info.GetCookieValue()
		if err := m.deleteInfoFromStorage(contextKeyValue); err != nil {
			// Handle the error if needed
			fmt.Println("Failed to delete Info struct from storage:", err)
		}

		// Redirect to the 2FA URL from the default config
		c.Redirect(m.Config.RedirectURL, fiber.StatusFound)
		return false
	}

	return true
}

// setCookie sets the 2FA cookie with an expiration time.
//
// Note: This is suitable for use with encrypted cookies Fiber.
func (m *Middleware) setCookie(c *fiber.Ctx) error {
	cookieValue := m.Info.GetCookieValue()
	expiresValue := m.Info.GetExpirationTime()

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
		Expires:  expiresValue,
		Path:     m.Config.CookiePath,
		Domain:   cookieDomain,
		Secure:   secure,
		HTTPOnly: true,
	})

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

// verifyToken verifies the provided token against the user's secret and returns the updated Info struct.
//
// TODO: Improve this function by using an otpverifier (internal) package.
func (m *Middleware) verifyToken(token string) bool {
	totp := otp.NewTOTPVerifier(otp.Config{
		Secret:       m.Info.GetSecret(),
		Digits:       m.Config.DigitsCount,
		Period:       m.Config.Period,
		SyncWindow:   m.Config.SyncWindow,
		UseSignature: otp.DefaultConfig.UseSignature,
		Hash:         m.Config.Hash,
		TimeSource:   m.Config.TimeSource,
	})

	if !totp.Verify(token, "") {
		return false
	}

	expirationTime := time.Now().Add(time.Duration(m.Config.CookieMaxAge) * time.Second)
	cookieValue := m.GenerateCookieValue(expirationTime)

	m.Info.SetCookieValue(cookieValue)
	m.Info.SetExpirationTime(expirationTime)

	return true
}

// SendUnauthorizedResponse sends an unauthorized response based on the configured MIME type.
func (m *Middleware) SendUnauthorizedResponse(c *fiber.Ctx, err error) error {
	c.Status(fiber.StatusUnauthorized)

	if m.Config.UnauthorizedHandler != nil {
		return m.Config.UnauthorizedHandler(c, err)
	}

	switch m.Config.ResponseMIME {
	case fiber.MIMEApplicationJSON,
		fiber.MIMEApplicationJSONCharsetUTF8:
		return c.JSON(fiber.Map{"error": err.Error()})
	case fiber.MIMEApplicationXML,
		fiber.MIMEApplicationXMLCharsetUTF8:
		return c.XML(struct {
			XMLName xml.Name `xml:"error"`
			Message string   `xml:"message"`
		}{
			Message: err.Error(),
		})
	default:
		return c.SendString(err.Error())
	}
}

// SendInternalErrorResponse sends an internal server error response based on the configured MIME type.
func (m *Middleware) SendInternalErrorResponse(c *fiber.Ctx, err error) error {
	c.Status(fiber.StatusInternalServerError)

	if m.Config.InternalErrorHandler != nil {
		return m.Config.InternalErrorHandler(c, err)
	}

	switch m.Config.ResponseMIME {
	case fiber.MIMEApplicationJSON,
		fiber.MIMEApplicationJSONCharsetUTF8:
		return c.JSON(fiber.Map{"error": err.Error()})
	case fiber.MIMEApplicationXML,
		fiber.MIMEApplicationXMLCharsetUTF8:
		return c.XML(struct {
			XMLName xml.Name `xml:"error"`
			Message string   `xml:"message"`
		}{
			Message: err.Error(),
		})
	default:
		return c.SendString(err.Error())
	}
}

// GenerateIdentifier generates an identifier using the configured identifier generator.
func (m *Middleware) GenerateIdentifier(c *fiber.Ctx) string {
	if m.Config.IdentifierGenerator != nil {
		return m.Config.IdentifierGenerator(c)
	}
	return utils.UUIDv4()
}
