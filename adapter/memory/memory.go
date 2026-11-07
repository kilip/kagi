package memory

import (
	"github.com/kilip/kagi/adaptertest"
)

// Stores bundles instances of all five primary in-memory storage ports.
type Stores struct {
	User         *UserStore
	Account      *AccountStore
	Session      *SessionStore
	Verification *VerificationStore
	RateLimit    *RateLimitStore
}

// New constructs a new Stores bundle initialized with the given options.
func New(opts ...Option) *Stores {
	return &Stores{
		User:         NewUserStore(opts...),
		Account:      NewAccountStore(opts...),
		Session:      NewSessionStore(opts...),
		Verification: NewVerificationStore(opts...),
		RateLimit:    NewRateLimitStore(opts...),
	}
}

// NewStores is an alias for New, constructing a Stores bundle.
func NewStores(opts ...Option) *Stores {
	return New(opts...)
}

// AsAdaptertestStores converts the concrete bundle into an adaptertest.Stores struct.
func (s *Stores) AsAdaptertestStores() adaptertest.Stores {
	return adaptertest.Stores{
		User:         s.User,
		Account:      s.Account,
		Session:      s.Session,
		Verification: s.Verification,
		RateLimit:    s.RateLimit,
	}
}
