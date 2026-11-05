package kagi

import "context"

// EmailMessage contains the details of an authentication email to be delivered.
type EmailMessage struct {
	To      string           `json:"to"`
	Subject string           `json:"subject"`
	Body    string           `json:"body"`
	Type    VerificationType `json:"type"`
	Code    string           `json:"code,omitempty"`
}

// Mailer defines the port for delivering authentication emails (OTP, password reset, etc.).
// Host applications implement this interface using their chosen email transport (SMTP, SES, Resend, etc.).
type Mailer interface {
	Send(ctx context.Context, msg EmailMessage) error
}
