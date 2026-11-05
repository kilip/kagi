// Package fiber provides Fiber handlers and middleware for Kagi.
//
//	@title						Kagi Authentication API
//	@version					1.0.0
//	@description				Reusable authentication HTTP API powered by Kagi.
//	@license.name				MIT
//	@license.url				https://opensource.org/licenses/MIT
//	@BasePath					/auth
//	@securityDefinitions.apikey	SessionCookie
//	@in							cookie
//	@name						kagi_session
//	@description				Opaque session token stored in an HttpOnly, Secure cookie.
package fiber
