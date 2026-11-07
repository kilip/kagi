package kagi_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kilip/kagi"
	"github.com/kilip/kagi/adapter/memory"
	"github.com/kilip/kagi/internal/clock"
	"github.com/kilip/kagi/internal/crypto"
)

// fastPasswordConfig returns fast Argon2id parameters for test execution.
func fastPasswordConfig() kagi.PasswordConfig {
	return kagi.PasswordConfig{
		MinLength:   8,
		MaxLength:   72,
		Memory:      8 * 1024, // 8 MB minimum for crypto package bounds
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

type spyUserStore struct {
	mu           sync.Mutex
	users        map[string]*kagi.User
	usersByEmail map[string]*kagi.User
	createCalls  []*kagi.User
	deleteCalls  []string
	getByEmailFn func(ctx context.Context, email string) (*kagi.User, error)
	createFn     func(ctx context.Context, user *kagi.User) error
	deleteFn     func(ctx context.Context, id string) error
	seq          int
}

func newSpyUserStore() *spyUserStore {
	return &spyUserStore{
		users:        make(map[string]*kagi.User),
		usersByEmail: make(map[string]*kagi.User),
	}
}

func (s *spyUserStore) Create(ctx context.Context, user *kagi.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createCalls = append(s.createCalls, user)
	if s.createFn != nil {
		return s.createFn(ctx, user)
	}
	s.seq++
	user.ID = "usr_" + strings.Repeat("0", 3-len(string(rune(s.seq)))) + string(rune('0'+s.seq))
	s.users[user.ID] = user
	s.usersByEmail[user.Email] = user
	return nil
}

func (s *spyUserStore) GetByID(ctx context.Context, id string) (*kagi.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return nil, kagi.ErrUserNotFound
	}
	return u, nil
}

func (s *spyUserStore) GetByEmail(ctx context.Context, email string) (*kagi.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getByEmailFn != nil {
		return s.getByEmailFn(ctx, email)
	}
	u, ok := s.usersByEmail[email]
	if !ok {
		return nil, kagi.ErrUserNotFound
	}
	return u, nil
}

func (s *spyUserStore) Update(ctx context.Context, user *kagi.User) error {
	return nil
}

func (s *spyUserStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteCalls = append(s.deleteCalls, id)
	if s.deleteFn != nil {
		return s.deleteFn(ctx, id)
	}
	if u, ok := s.users[id]; ok {
		delete(s.usersByEmail, u.Email)
		delete(s.users, id)
	}
	return nil
}

type spyAccountStore struct {
	mu          sync.Mutex
	accounts    map[string]*kagi.Account
	createCalls []*kagi.Account
	createFn    func(ctx context.Context, account *kagi.Account) error
	getByProvFn func(ctx context.Context, provider, providerAccountID string) (*kagi.Account, error)
	listByUIDFn func(ctx context.Context, userID string) ([]*kagi.Account, error)
	seq         int
}

func newSpyAccountStore() *spyAccountStore {
	return &spyAccountStore{
		accounts: make(map[string]*kagi.Account),
	}
}

func (s *spyAccountStore) Create(ctx context.Context, account *kagi.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.createCalls = append(s.createCalls, account)
	if s.createFn != nil {
		return s.createFn(ctx, account)
	}
	s.seq++
	account.ID = "acc_" + string(rune('0'+s.seq))
	s.accounts[account.Provider+":"+account.ProviderAccountID] = account
	return nil
}

func (s *spyAccountStore) GetByProvider(ctx context.Context, provider, providerAccountID string) (*kagi.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.getByProvFn != nil {
		return s.getByProvFn(ctx, provider, providerAccountID)
	}
	a, ok := s.accounts[provider+":"+providerAccountID]
	if !ok {
		return nil, kagi.ErrAccountNotFound
	}
	return a, nil
}

func (s *spyAccountStore) ListByUserID(ctx context.Context, userID string) ([]*kagi.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listByUIDFn != nil {
		return s.listByUIDFn(ctx, userID)
	}
	var res []*kagi.Account
	for _, a := range s.accounts {
		if a.UserID == userID {
			res = append(res, a)
		}
	}
	return res, nil
}

func (s *spyAccountStore) Update(ctx context.Context, account *kagi.Account) error {
	return nil
}

func (s *spyAccountStore) Delete(ctx context.Context, id string) error {
	return nil
}

func (s *spyAccountStore) CountByUserID(ctx context.Context, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, a := range s.accounts {
		if a.UserID == userID {
			count++
		}
	}
	return count, nil
}

func (s *spyAccountStore) DeleteByUserID(ctx context.Context, userID string) error {
	return nil
}
func TestCredentialService_SignUp_ContextCanceled(t *testing.T) {
	userStore := newSpyUserStore()
	accountStore := newSpyAccountStore()
	svc := kagi.NewCredentialService(userStore, accountStore, fastPasswordConfig(), clock.RealClock{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	user, err := svc.SignUp(ctx, kagi.SignUpInput{
		Email:    "test@example.com",
		Password: "password123",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func TestCredentialService_SignUp_EmailValidation(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{name: "empty string", email: ""},
		{name: "spaces only", email: "   \t\n  "},
		{name: "missing at symbol", email: "plainaddress"},
		{name: "missing local part", email: "@example.com"},
		{name: "missing domain part", email: "user@"},
		{name: "missing domain tld dot", email: "user@localhost"},
		{name: "domain starts with dot", email: "user@.example.com"},
		{name: "domain ends with dot", email: "user@example.com."},
		{name: "consecutive dots in domain", email: "user@example..com"},
		{name: "domain label starts with hyphen", email: "user@-example.com"},
		{name: "domain label ends with hyphen", email: "user@example-.com"},
		{name: "spaces in local part", email: "user name@example.com"},
		{name: "angle brackets display name", email: "User <user@example.com>"},
		{name: "multiple at symbols", email: "user@domain@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userStore := newSpyUserStore()
			accountStore := newSpyAccountStore()
			svc := kagi.NewCredentialService(userStore, accountStore, fastPasswordConfig(), clock.RealClock{})

			user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
				Email:    tt.email,
				Password: "password123",
				Name:     "Test User",
			})
			if !errors.Is(err, kagi.ErrInvalidCredentials) {
				t.Fatalf("expected ErrInvalidCredentials for email %q, got %v", tt.email, err)
			}
			if user != nil {
				t.Fatalf("expected nil user, got %+v", user)
			}
			if len(userStore.createCalls) > 0 {
				t.Fatalf("user store should not be called on invalid email")
			}
		})
	}
}

func TestCredentialService_SignUp_PasswordLengthValidation(t *testing.T) {
	tests := []struct {
		name     string
		password string
		pwdCfg   kagi.PasswordConfig
		wantErr  error
	}{
		{
			name:     "shorter than default MinLength 8",
			password: "1234567",
			pwdCfg:   fastPasswordConfig(),
			wantErr:  kagi.ErrPasswordTooWeak,
		},
		{
			name:     "empty password",
			password: "",
			pwdCfg:   fastPasswordConfig(),
			wantErr:  kagi.ErrPasswordTooWeak,
		},
		{
			name:     "longer than default MaxLength 72",
			password: strings.Repeat("a", 73),
			pwdCfg:   fastPasswordConfig(),
			wantErr:  kagi.ErrPasswordTooWeak,
		},
		{
			name:     "shorter than custom MinLength 10",
			password: "123456789",
			pwdCfg: func() kagi.PasswordConfig {
				cfg := fastPasswordConfig()
				cfg.MinLength = 10
				return cfg
			}(),
			wantErr: kagi.ErrPasswordTooWeak,
		},
		{
			name:     "longer than custom MaxLength 20",
			password: strings.Repeat("x", 21),
			pwdCfg: func() kagi.PasswordConfig {
				cfg := fastPasswordConfig()
				cfg.MaxLength = 20
				return cfg
			}(),
			wantErr: kagi.ErrPasswordTooWeak,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userStore := newSpyUserStore()
			accountStore := newSpyAccountStore()
			svc := kagi.NewCredentialService(userStore, accountStore, tt.pwdCfg, clock.RealClock{})

			user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
				Email:    "valid@example.com",
				Password: tt.password,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("expected %v, got %v", tt.wantErr, err)
			}
			if user != nil {
				t.Fatalf("expected nil user, got %+v", user)
			}
			if len(userStore.createCalls) > 0 {
				t.Fatalf("user store should not be called on invalid password")
			}
		})
	}
}

func TestCredentialService_SignUp_PreHashDuplicateEmailCheck(t *testing.T) {
	userStore := newSpyUserStore()
	accountStore := newSpyAccountStore()
	// Pre-seed user in userStore
	userStore.usersByEmail["alice@example.com"] = &kagi.User{
		ID:    "usr_existing",
		Email: "alice@example.com",
	}

	// Use large iterations/memory that would take seconds if hashing occurred
	pwdCfg := kagi.PasswordConfig{
		MinLength:   8,
		MaxLength:   72,
		Memory:      64 * 1024,
		Iterations:  10,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
	svc := kagi.NewCredentialService(userStore, accountStore, pwdCfg, clock.RealClock{})

	start := time.Now()
	user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "Alice@Example.com",
		Password: "password123",
	})
	duration := time.Since(start)

	if !errors.Is(err, kagi.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists, got %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
	if len(userStore.createCalls) > 0 {
		t.Fatalf("users.Create must not be called when duplicate email exists")
	}
	if len(accountStore.createCalls) > 0 {
		t.Fatalf("accounts.Create must not be called when duplicate email exists")
	}
	// Argon2 with 10 iterations / 64MB takes > 200ms. Pre-hash check should return in < 50ms.
	if duration > 150*time.Millisecond {
		t.Errorf("pre-hash duplicate check took too long (%v), password may have been hashed", duration)
	}
}

func TestCredentialService_SignUp_SuccessAndNormalization(t *testing.T) {
	userStore := newSpyUserStore()
	accountStore := newSpyAccountStore()
	fakeClk := clock.NewFake(time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC))
	svc := kagi.NewCredentialService(userStore, accountStore, fastPasswordConfig(), fakeClk)

	rawPassword := "SecureP@ssw0rd!"
	user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "   Bob.Smith@EXAMPLE.com   ",
		Password: rawPassword,
		Name:     "  Bob Smith  ",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil {
		t.Fatal("expected non-nil user")
	}

	// Verify User attributes
	if user.Email != "bob.smith@example.com" {
		t.Errorf("expected normalized email 'bob.smith@example.com', got %q", user.Email)
	}
	if user.Name != "Bob Smith" {
		t.Errorf("expected trimmed name 'Bob Smith', got %q", user.Name)
	}
	if user.EmailVerified {
		t.Errorf("expected EmailVerified to be false")
	}
	if user.TwoFactorEnabled {
		t.Errorf("expected TwoFactorEnabled to be false")
	}
	if user.ID == "" {
		t.Errorf("expected non-empty user ID")
	}

	// Verify Account record created
	if len(accountStore.createCalls) != 1 {
		t.Fatalf("expected 1 account created, got %d", len(accountStore.createCalls))
	}
	acc := accountStore.createCalls[0]
	if acc.UserID != user.ID {
		t.Errorf("expected account.UserID %q, got %q", user.ID, acc.UserID)
	}
	if acc.Provider != "credential" {
		t.Errorf("expected provider 'credential', got %q", acc.Provider)
	}
	if acc.ProviderAccountID != "bob.smith@example.com" {
		t.Errorf("expected ProviderAccountID 'bob.smith@example.com', got %q", acc.ProviderAccountID)
	}
	if !strings.HasPrefix(acc.PasswordHash, "$argon2id$v=19$") {
		t.Errorf("expected argon2id hash, got %q", acc.PasswordHash)
	}

	// Verify password hash matches raw password
	match, err := crypto.VerifyPassword(rawPassword, acc.PasswordHash)
	if err != nil {
		t.Fatalf("crypto.VerifyPassword error: %v", err)
	}
	if !match {
		t.Errorf("expected password to match stored hash")
	}

	// Verify wrong password does not match
	matchWrong, err := crypto.VerifyPassword("wrong-password", acc.PasswordHash)
	if err != nil {
		t.Fatalf("crypto.VerifyPassword on wrong password error: %v", err)
	}
	if matchWrong {
		t.Errorf("expected wrong password not to match stored hash")
	}

	// Verify User struct has no password fields or hashes in JSON serialization
	userJSON, err := json.Marshal(user)
	if err != nil {
		t.Fatalf("failed to marshal user: %v", err)
	}
	userJSONStr := string(userJSON)
	if strings.Contains(userJSONStr, "password") || strings.Contains(userJSONStr, "hash") {
		t.Errorf("user JSON contains password or hash leaks: %s", userJSONStr)
	}
}

func TestCredentialService_SignUp_CompensatoryDeletionOnAccountError(t *testing.T) {
	dbErr := errors.New("simulated account store failure")

	userStore := newSpyUserStore()
	accountStore := newSpyAccountStore()
	accountStore.createFn = func(ctx context.Context, account *kagi.Account) error {
		return dbErr
	}

	svc := kagi.NewCredentialService(userStore, accountStore, fastPasswordConfig(), clock.RealClock{})

	user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "charlie@example.com",
		Password: "password123",
	})

	if !errors.Is(err, dbErr) {
		t.Fatalf("expected dbErr, got %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}

	// Verify compensatory deletion occurred
	if len(userStore.createCalls) != 1 {
		t.Fatalf("expected 1 user creation call, got %d", len(userStore.createCalls))
	}
	createdID := userStore.createCalls[0].ID
	if len(userStore.deleteCalls) != 1 {
		t.Fatalf("expected 1 compensatory delete call, got %d", len(userStore.deleteCalls))
	}
	if userStore.deleteCalls[0] != createdID {
		t.Errorf("expected compensatory delete of user ID %q, got %q", createdID, userStore.deleteCalls[0])
	}
	// Verify user was actually removed from userStore
	if _, ok := userStore.users[createdID]; ok {
		t.Errorf("expected user %q to be deleted from userStore", createdID)
	}
}

func TestCredentialService_SignUp_CompensatoryDeletionMapsAccountAlreadyExists(t *testing.T) {
	userStore := newSpyUserStore()
	accountStore := newSpyAccountStore()
	accountStore.createFn = func(ctx context.Context, account *kagi.Account) error {
		return kagi.ErrAccountAlreadyExists
	}

	svc := kagi.NewCredentialService(userStore, accountStore, fastPasswordConfig(), clock.RealClock{})

	user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "dave@example.com",
		Password: "password123",
	})

	if !errors.Is(err, kagi.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists, got %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}

	// Verify compensatory deletion occurred
	if len(userStore.createCalls) != 1 {
		t.Fatalf("expected 1 user creation call, got %d", len(userStore.createCalls))
	}
	createdID := userStore.createCalls[0].ID
	if len(userStore.deleteCalls) != 1 {
		t.Fatalf("expected 1 compensatory delete call, got %d", len(userStore.deleteCalls))
	}
	if userStore.deleteCalls[0] != createdID {
		t.Errorf("expected compensatory delete of user ID %q, got %q", createdID, userStore.deleteCalls[0])
	}
}

func TestCredentialService_SignUp_UserStoreCreateError(t *testing.T) {
	dbErr := errors.New("simulated user store failure")

	userStore := newSpyUserStore()
	userStore.createFn = func(ctx context.Context, user *kagi.User) error {
		return dbErr
	}
	accountStore := newSpyAccountStore()

	svc := kagi.NewCredentialService(userStore, accountStore, fastPasswordConfig(), clock.RealClock{})

	user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "eve@example.com",
		Password: "password123",
	})

	if !errors.Is(err, dbErr) {
		t.Fatalf("expected dbErr, got %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
	if len(accountStore.createCalls) > 0 {
		t.Fatalf("accounts.Create must not be called if users.Create fails")
	}
	if len(userStore.deleteCalls) > 0 {
		t.Fatalf("users.Delete must not be called if users.Create fails")
	}
}

func TestCredentialService_SignUp_IntegrationWithMemoryStores(t *testing.T) {
	memClk := clock.NewFake(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC))
	userStore := memory.NewUserStore(memory.WithClock(memClk))
	accountStore := memory.NewAccountStore(memory.WithClock(memClk))
	svc := kagi.NewCredentialService(userStore, accountStore, fastPasswordConfig(), memClk)

	// Successful sign-up
	user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "frank@example.com",
		Password: "my-secret-password",
		Name:     "Frank Castle",
	})
	if err != nil {
		t.Fatalf("unexpected sign up error: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected user ID to be assigned")
	}

	// Stored in UserStore
	storedUser, err := userStore.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("failed to retrieve stored user: %v", err)
	}
	if storedUser.Email != "frank@example.com" {
		t.Errorf("expected email 'frank@example.com', got %q", storedUser.Email)
	}

	// Stored in AccountStore
	storedAccount, err := accountStore.GetByProvider(context.Background(), "credential", "frank@example.com")
	if err != nil {
		t.Fatalf("failed to retrieve stored account: %v", err)
	}
	if storedAccount.UserID != user.ID {
		t.Errorf("expected account UserID %q, got %q", user.ID, storedAccount.UserID)
	}

	// Duplicate sign-up with same email returns ErrEmailAlreadyExists
	_, dupErr := svc.SignUp(context.Background(), kagi.SignUpInput{
		Email:    "frank@example.com",
		Password: "another-password",
	})
	if !errors.Is(dupErr, kagi.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists on duplicate sign-up, got %v", dupErr)
	}
}
