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
	"github.com/kilip/kagi/mock"
	"go.uber.org/mock/gomock"
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

func TestCredentialService_SignUp_TableDriven(t *testing.T) {
	fixedTime := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)

	storeErrGet := errors.New("storage: failed to read user")
	storeErrCreateUser := errors.New("storage: failed to insert user")
	storeErrCreateAccount := errors.New("storage: failed to insert account")

	type testCase struct {
		name        string
		ctx         func() (context.Context, context.CancelFunc)
		input       kagi.SignUpInput
		pwdConfig   *kagi.PasswordConfig
		setupMocks  func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account)
		wantErr     error
		checkResult func(t *testing.T, user *kagi.User, capturedAccount *kagi.Account)
	}

	tests := []testCase{
		{
			name: "happy_path_standard_signup",
			input: kagi.SignUpInput{
				Email:    "  Alice.Smith@Example.COM  ",
				Password: "ValidP@ssw0rd123!",
				Name:     "  Alice Smith  ",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().
					GetByEmail(gomock.Any(), "alice.smith@example.com").
					Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
					DoAndReturn(func(ctx context.Context, u *kagi.User) error {
						u.ID = "usr_alice_123"
						return nil
					})
				aStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).
					DoAndReturn(func(ctx context.Context, acc *kagi.Account) error {
						*capturedAccount = acc
						return nil
					})
			},
			wantErr: nil,
			checkResult: func(t *testing.T, user *kagi.User, capturedAccount *kagi.Account) {
				if user.ID != "usr_alice_123" {
					t.Errorf("expected user.ID 'usr_alice_123', got %q", user.ID)
				}
				if user.Email != "alice.smith@example.com" {
					t.Errorf("expected normalized email 'alice.smith@example.com', got %q", user.Email)
				}
				if user.Name != "Alice Smith" {
					t.Errorf("expected trimmed name 'Alice Smith', got %q", user.Name)
				}
				if user.EmailVerified {
					t.Errorf("expected EmailVerified to be false")
				}
				if user.TwoFactorEnabled {
					t.Errorf("expected TwoFactorEnabled to be false")
				}
				if capturedAccount == nil {
					t.Fatal("expected captured account")
				}
				if capturedAccount.UserID != "usr_alice_123" {
					t.Errorf("expected account.UserID 'usr_alice_123', got %q", capturedAccount.UserID)
				}
				if capturedAccount.Provider != "credential" {
					t.Errorf("expected provider 'credential', got %q", capturedAccount.Provider)
				}
				if capturedAccount.ProviderAccountID != "alice.smith@example.com" {
					t.Errorf("expected ProviderAccountID 'alice.smith@example.com', got %q", capturedAccount.ProviderAccountID)
				}
			},
		},
		{
			name: "whitespace_and_case_normalization",
			input: kagi.SignUpInput{
				Email:    " \t  BOB.Builder@SUB.EXAMPLE.COM \n ",
				Password: "ValidP@ssw0rd8",
				Name:     " \t Bob The Builder \n ",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().
					GetByEmail(gomock.Any(), "bob.builder@sub.example.com").
					Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
					DoAndReturn(func(ctx context.Context, u *kagi.User) error {
						u.ID = "usr_bob"
						return nil
					})
				aStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).
					DoAndReturn(func(ctx context.Context, acc *kagi.Account) error {
						*capturedAccount = acc
						return nil
					})
			},
			checkResult: func(t *testing.T, user *kagi.User, capturedAccount *kagi.Account) {
				if user.Email != "bob.builder@sub.example.com" {
					t.Errorf("expected email 'bob.builder@sub.example.com', got %q", user.Email)
				}
				if user.Name != "Bob The Builder" {
					t.Errorf("expected name 'Bob The Builder', got %q", user.Name)
				}
				if capturedAccount.ProviderAccountID != "bob.builder@sub.example.com" {
					t.Errorf("expected account ProviderAccountID 'bob.builder@sub.example.com', got %q", capturedAccount.ProviderAccountID)
				}
			},
		},
		{
			name: "password_boundary_exact_min_length_8",
			input: kagi.SignUpInput{
				Email:    "min8@example.com",
				Password: "12345678",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().GetByEmail(gomock.Any(), "min8@example.com").Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).DoAndReturn(func(ctx context.Context, u *kagi.User) error {
					u.ID = "usr_min8"
					return nil
				})
				aStore.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).DoAndReturn(func(ctx context.Context, acc *kagi.Account) error {
					*capturedAccount = acc
					return nil
				})
			},
		},
		{
			name: "password_boundary_exact_max_length_72",
			input: kagi.SignUpInput{
				Email:    "max72@example.com",
				Password: strings.Repeat("A", 72),
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().GetByEmail(gomock.Any(), "max72@example.com").Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).DoAndReturn(func(ctx context.Context, u *kagi.User) error {
					u.ID = "usr_max72"
					return nil
				})
				aStore.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).DoAndReturn(func(ctx context.Context, acc *kagi.Account) error {
					*capturedAccount = acc
					return nil
				})
			},
		},
		{
			name: "password_boundary_multibyte_utf8_runes",
			input: kagi.SignUpInput{
				Email:    "utf8@example.com",
				Password: "パスワード１２３", // 8 runes, 24 bytes
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().GetByEmail(gomock.Any(), "utf8@example.com").Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).DoAndReturn(func(ctx context.Context, u *kagi.User) error {
					u.ID = "usr_utf8"
					return nil
				})
				aStore.EXPECT().Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).DoAndReturn(func(ctx context.Context, acc *kagi.Account) error {
					*capturedAccount = acc
					return nil
				})
			},
		},
		{
			name: "password_too_short_7_runes",
			input: kagi.SignUpInput{
				Email:    "short@example.com",
				Password: "1234567",
			},
			wantErr: kagi.ErrPasswordTooWeak,
		},
		{
			name: "password_empty",
			input: kagi.SignUpInput{
				Email:    "empty-pw@example.com",
				Password: "",
			},
			wantErr: kagi.ErrPasswordTooWeak,
		},
		{
			name: "password_too_long_73_runes",
			input: kagi.SignUpInput{
				Email:    "long@example.com",
				Password: strings.Repeat("B", 73),
			},
			wantErr: kagi.ErrPasswordTooWeak,
		},
		{
			name: "password_custom_config_min_length_violation",
			input: kagi.SignUpInput{
				Email:    "custom-min@example.com",
				Password: "12345678901", // 11 runes
			},
			pwdConfig: func() *kagi.PasswordConfig {
				cfg := fastPasswordConfig()
				cfg.MinLength = 12
				return &cfg
			}(),
			wantErr: kagi.ErrPasswordTooWeak,
		},
		{
			name: "password_custom_config_max_length_violation",
			input: kagi.SignUpInput{
				Email:    "custom-max@example.com",
				Password: "12345678901", // 11 runes
			},
			pwdConfig: func() *kagi.PasswordConfig {
				cfg := fastPasswordConfig()
				cfg.MaxLength = 10
				return &cfg
			}(),
			wantErr: kagi.ErrPasswordTooWeak,
		},
		{
			name: "password_default_config_fallback_when_zero_valued",
			input: kagi.SignUpInput{
				Email:    "fallback@example.com",
				Password: "12345", // 5 runes < default 8
			},
			pwdConfig: &kagi.PasswordConfig{}, // zero-valued
			wantErr:   kagi.ErrPasswordTooWeak,
		},
		{
			name: "invalid_email_empty",
			input: kagi.SignUpInput{
				Email:    "",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_spaces_only",
			input: kagi.SignUpInput{
				Email:    "   \t\n   ",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_missing_at",
			input: kagi.SignUpInput{
				Email:    "plainaddress",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_missing_local_part",
			input: kagi.SignUpInput{
				Email:    "@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_missing_domain_part",
			input: kagi.SignUpInput{
				Email:    "user@",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_missing_domain_tld_dot",
			input: kagi.SignUpInput{
				Email:    "user@localhost",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_domain_starts_with_dot",
			input: kagi.SignUpInput{
				Email:    "user@.example.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_domain_ends_with_dot",
			input: kagi.SignUpInput{
				Email:    "user@example.com.",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_consecutive_dots",
			input: kagi.SignUpInput{
				Email:    "user@example..com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_hyphen_leading_in_domain_label",
			input: kagi.SignUpInput{
				Email:    "user@-example.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_hyphen_trailing_in_domain_label",
			input: kagi.SignUpInput{
				Email:    "user@example-.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_spaces_in_local_part",
			input: kagi.SignUpInput{
				Email:    "user name@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_display_name_angle_brackets",
			input: kagi.SignUpInput{
				Email:    "User <user@example.com>",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_multiple_at_symbols",
			input: kagi.SignUpInput{
				Email:    "user@domain@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "invalid_email_exceeds_max_length_254",
			input: kagi.SignUpInput{
				Email:    strings.Repeat("a", 246) + "@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: kagi.ErrInvalidCredentials,
		},
		{
			name: "duplicate_email_detected_on_initial_read",
			input: kagi.SignUpInput{
				Email:    "existing@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().
					GetByEmail(gomock.Any(), "existing@example.com").
					Return(&kagi.User{ID: "usr_prev", Email: "existing@example.com"}, nil)
			},
			wantErr: kagi.ErrEmailAlreadyExists,
		},
		{
			name: "duplicate_email_detected_on_account_create_with_compensation",
			input: kagi.SignUpInput{
				Email:    "race@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().
					GetByEmail(gomock.Any(), "race@example.com").
					Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
					DoAndReturn(func(ctx context.Context, u *kagi.User) error {
						u.ID = "usr_race_456"
						return nil
					})
				aStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).
					Return(kagi.ErrAccountAlreadyExists)
				uStore.EXPECT().
					Delete(gomock.Any(), "usr_race_456").
					Return(nil)
			},
			wantErr: kagi.ErrEmailAlreadyExists,
		},
		{
			name: "user_store_get_by_email_unexpected_error",
			input: kagi.SignUpInput{
				Email:    "userstore-err@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().
					GetByEmail(gomock.Any(), "userstore-err@example.com").
					Return(nil, storeErrGet)
			},
			wantErr: storeErrGet,
		},
		{
			name: "user_store_create_unexpected_error",
			input: kagi.SignUpInput{
				Email:    "createuser-err@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().
					GetByEmail(gomock.Any(), "createuser-err@example.com").
					Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
					Return(storeErrCreateUser)
			},
			wantErr: storeErrCreateUser,
		},
		{
			name: "account_store_create_failure_with_compensatory_rollback",
			input: kagi.SignUpInput{
				Email:    "createacc-err@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().
					GetByEmail(gomock.Any(), "createacc-err@example.com").
					Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
					DoAndReturn(func(ctx context.Context, u *kagi.User) error {
						u.ID = "usr_acc_fail"
						return nil
					})
				aStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).
					Return(storeErrCreateAccount)
				uStore.EXPECT().
					Delete(gomock.Any(), "usr_acc_fail").
					Return(nil)
			},
			wantErr: storeErrCreateAccount,
		},
		{
			name: "context_already_canceled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			input: kagi.SignUpInput{
				Email:    "canceled@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: context.Canceled,
		},
		{
			name: "context_already_deadline_exceeded",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Hour))
				return ctx, cancel
			},
			input: kagi.SignUpInput{
				Email:    "expired@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			wantErr: context.DeadlineExceeded,
		},
		{
			name: "context_canceled_during_user_create",
			input: kagi.SignUpInput{
				Email:    "canceled-during-create@example.com",
				Password: "ValidP@ssw0rd123!",
			},
			setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore, capturedAccount **kagi.Account) {
				uStore.EXPECT().
					GetByEmail(gomock.Any(), "canceled-during-create@example.com").
					Return(nil, kagi.ErrUserNotFound)
				uStore.EXPECT().
					Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
					Return(context.Canceled)
			},
			wantErr: context.Canceled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			uStore := mock.NewMockUserStore(ctrl)
			aStore := mock.NewMockAccountStore(ctrl)
			fakeClk := clock.NewFake(fixedTime)

			pwdCfg := fastPasswordConfig()
			if tc.pwdConfig != nil {
				pwdCfg = *tc.pwdConfig
			}

			svc := kagi.NewCredentialService(uStore, aStore, pwdCfg, fakeClk)

			var capturedAccount *kagi.Account
			if tc.setupMocks != nil {
				tc.setupMocks(ctrl, uStore, aStore, &capturedAccount)
			}

			ctx := context.Background()
			if tc.ctx != nil {
				var cancel context.CancelFunc
				ctx, cancel = tc.ctx()
				defer cancel()
			}

			user, err := svc.SignUp(ctx, tc.input)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error wrapping %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected error wrapping %v, got %v", tc.wantErr, err)
				}
				if tc.input.Password != "" && strings.Contains(err.Error(), tc.input.Password) {
					t.Errorf("security violation: error message contains plain password %q: %v", tc.input.Password, err)
				}
				if user != nil {
					t.Errorf("expected nil user on error, got %+v", user)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if user == nil {
					t.Fatal("expected non-nil user on success")
				}

				// Security check: JSON serialization must not leak password or hash
				userJSON, mErr := json.Marshal(user)
				if mErr != nil {
					t.Fatalf("failed to marshal user to JSON: %v", mErr)
				}
				userJSONStr := string(userJSON)
				lowerJSON := strings.ToLower(userJSONStr)
				if strings.Contains(lowerJSON, "password") {
					t.Errorf("security violation: user JSON contains 'password': %s", userJSONStr)
				}
				if strings.Contains(lowerJSON, "hash") {
					t.Errorf("security violation: user JSON contains 'hash': %s", userJSONStr)
				}
				if tc.input.Password != "" && strings.Contains(userJSONStr, tc.input.Password) {
					t.Errorf("security violation: user JSON contains plain password %q: %s", tc.input.Password, userJSONStr)
				}
				if capturedAccount != nil && capturedAccount.PasswordHash != "" {
					if strings.Contains(userJSONStr, capturedAccount.PasswordHash) {
						t.Errorf("security violation: user JSON contains password hash: %s", userJSONStr)
					}
					// Security check: crypto.VerifyPassword evaluates to true for correct password
					match, vErr := crypto.VerifyPassword(tc.input.Password, capturedAccount.PasswordHash)
					if vErr != nil {
						t.Fatalf("crypto.VerifyPassword error: %v", vErr)
					}
					if !match {
						t.Errorf("expected crypto.VerifyPassword to return true for valid password")
					}
					// Security check: crypto.VerifyPassword evaluates to false for wrong password
					matchWrong, vErr := crypto.VerifyPassword("Wrong"+tc.input.Password, capturedAccount.PasswordHash)
					if vErr != nil {
						t.Fatalf("crypto.VerifyPassword with wrong password error: %v", vErr)
					}
					if matchWrong {
						t.Errorf("expected crypto.VerifyPassword to return false for wrong password")
					}
				}
			}

			if tc.checkResult != nil {
				tc.checkResult(t, user, capturedAccount)
			}
		})
	}
}

func TestCredentialService_SignUp_SecurityContracts(t *testing.T) {
	fakeClk := clock.NewFake(time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC))

	t.Run("crypto.VerifyPassword evaluates to true for correct password and false for wrong password", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		uStore := mock.NewMockUserStore(ctrl)
		aStore := mock.NewMockAccountStore(ctrl)
		svc := kagi.NewCredentialService(uStore, aStore, fastPasswordConfig(), fakeClk)

		secretPassword := "SuperSecretP@ssw0rd!2026"
		email := "sec-verify@example.com"

		var capturedAccount *kagi.Account
		uStore.EXPECT().
			GetByEmail(gomock.Any(), email).
			Return(nil, kagi.ErrUserNotFound)
		uStore.EXPECT().
			Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
			DoAndReturn(func(ctx context.Context, u *kagi.User) error {
				u.ID = "usr_sec_verify"
				return nil
			})
		aStore.EXPECT().
			Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).
			DoAndReturn(func(ctx context.Context, acc *kagi.Account) error {
				capturedAccount = acc
				return nil
			})

		user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
			Email:    email,
			Password: secretPassword,
			Name:     "Security User",
		})
		if err != nil {
			t.Fatalf("unexpected SignUp error: %v", err)
		}
		if user == nil || capturedAccount == nil {
			t.Fatal("expected non-nil user and capturedAccount")
		}

		// Contract: crypto.VerifyPassword(password, storedHash) evaluates to true
		match, err := crypto.VerifyPassword(secretPassword, capturedAccount.PasswordHash)
		if err != nil {
			t.Fatalf("crypto.VerifyPassword error: %v", err)
		}
		if !match {
			t.Errorf("crypto.VerifyPassword(%q, storedHash) evaluated to false, expected true", secretPassword)
		}

		// Contract: crypto.VerifyPassword(wrongPassword, storedHash) evaluates to false
		wrongPasswords := []string{
			"WrongPassword123!",
			secretPassword + "x",
			secretPassword[:len(secretPassword)-1],
			strings.ToLower(secretPassword),
			"",
		}
		for _, wrong := range wrongPasswords {
			m, err := crypto.VerifyPassword(wrong, capturedAccount.PasswordHash)
			if err != nil {
				t.Fatalf("crypto.VerifyPassword(%q) error: %v", wrong, err)
			}
			if m {
				t.Errorf("crypto.VerifyPassword(%q, storedHash) evaluated to true, expected false", wrong)
			}
		}
	})

	t.Run("*User JSON serialization does not contain password or hash substrings", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		uStore := mock.NewMockUserStore(ctrl)
		aStore := mock.NewMockAccountStore(ctrl)
		svc := kagi.NewCredentialService(uStore, aStore, fastPasswordConfig(), fakeClk)

		secretPassword := "SensitivePassword123!"
		var capturedAccount *kagi.Account
		uStore.EXPECT().
			GetByEmail(gomock.Any(), "user-json-sec@example.com").
			Return(nil, kagi.ErrUserNotFound)
		uStore.EXPECT().
			Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
			DoAndReturn(func(ctx context.Context, u *kagi.User) error {
				u.ID = "usr_json_sec"
				return nil
			})
		aStore.EXPECT().
			Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).
			DoAndReturn(func(ctx context.Context, acc *kagi.Account) error {
				capturedAccount = acc
				return nil
			})

		user, err := svc.SignUp(context.Background(), kagi.SignUpInput{
			Email:    "user-json-sec@example.com",
			Password: secretPassword,
			Name:     "JSON Security Tester",
		})
		if err != nil {
			t.Fatalf("unexpected SignUp error: %v", err)
		}

		userJSON, err := json.Marshal(user)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		jsonStr := string(userJSON)
		lowerJSON := strings.ToLower(jsonStr)

		if strings.Contains(lowerJSON, "password") {
			t.Errorf("security violation: user JSON contains 'password': %s", jsonStr)
		}
		if strings.Contains(lowerJSON, "hash") {
			t.Errorf("security violation: user JSON contains 'hash': %s", jsonStr)
		}
		if strings.Contains(jsonStr, secretPassword) {
			t.Errorf("security violation: user JSON leaked plain password: %s", jsonStr)
		}
		if capturedAccount != nil && strings.Contains(jsonStr, capturedAccount.PasswordHash) {
			t.Errorf("security violation: user JSON leaked password hash: %s", jsonStr)
		}

		// Also check allowed top-level keys
		var parsed map[string]any
		if err := json.Unmarshal(userJSON, &parsed); err != nil {
			t.Fatalf("json.Unmarshal failed: %v", err)
		}
		for k := range parsed {
			switch k {
			case "id", "email", "name", "email_verified", "two_factor_enabled", "created_at", "updated_at":
				// allowed
			default:
				t.Errorf("unexpected field %q in serialized *User: %v", k, parsed)
			}
		}
	})

	t.Run("error messages never leak plain passwords", func(t *testing.T) {
		weakPasswords := []string{
			"short",
			"123",
			"",
			strings.Repeat("Z", 75),
		}
		for _, wp := range weakPasswords {
			t.Run("weak_password/"+wp, func(t *testing.T) {
				svc := kagi.NewCredentialService(nil, nil, fastPasswordConfig(), fakeClk)
				_, err := svc.SignUp(context.Background(), kagi.SignUpInput{
					Email:    "check@example.com",
					Password: wp,
				})
				if !errors.Is(err, kagi.ErrPasswordTooWeak) {
					t.Fatalf("expected ErrPasswordTooWeak, got %v", err)
				}
				if wp != "" && strings.Contains(err.Error(), wp) {
					t.Fatalf("security violation: error message leaked plain password %q: %v", wp, err)
				}
			})
		}

		secrets := []string{
			"MySecret123!",
			"P@ssw0rd#With$ymbo1s!",
			"ExtremelyLongSecretPasswordString9876543210!",
		}

		scenarios := []struct {
			name       string
			setupMocks func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore)
			input      func(secret string) kagi.SignUpInput
		}{
			{
				name:       "invalid email error",
				setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore) {},
				input: func(secret string) kagi.SignUpInput {
					return kagi.SignUpInput{Email: "not-an-email", Password: secret}
				},
			},
			{
				name: "duplicate email on read error",
				setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore) {
					uStore.EXPECT().
						GetByEmail(gomock.Any(), "dup-err@example.com").
						Return(&kagi.User{ID: "usr_existing", Email: "dup-err@example.com"}, nil)
				},
				input: func(secret string) kagi.SignUpInput {
					return kagi.SignUpInput{Email: "dup-err@example.com", Password: secret}
				},
			},
			{
				name: "user store error",
				setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore) {
					uStore.EXPECT().
						GetByEmail(gomock.Any(), "store-err@example.com").
						Return(nil, errors.New("db error"))
				},
				input: func(secret string) kagi.SignUpInput {
					return kagi.SignUpInput{Email: "store-err@example.com", Password: secret}
				},
			},
			{
				name: "account already exists on create error",
				setupMocks: func(ctrl *gomock.Controller, uStore *mock.MockUserStore, aStore *mock.MockAccountStore) {
					uStore.EXPECT().
						GetByEmail(gomock.Any(), "acc-dup@example.com").
						Return(nil, kagi.ErrUserNotFound)
					uStore.EXPECT().
						Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.User{})).
						DoAndReturn(func(ctx context.Context, u *kagi.User) error {
							u.ID = "usr_acc_dup"
							return nil
						})
					aStore.EXPECT().
						Create(gomock.Any(), gomock.AssignableToTypeOf(&kagi.Account{})).
						Return(kagi.ErrAccountAlreadyExists)
					uStore.EXPECT().
						Delete(gomock.Any(), "usr_acc_dup").
						Return(nil)
				},
				input: func(secret string) kagi.SignUpInput {
					return kagi.SignUpInput{Email: "acc-dup@example.com", Password: secret}
				},
			},
		}

		for _, secret := range secrets {
			for _, sc := range scenarios {
				t.Run(sc.name+"/"+secret, func(t *testing.T) {
					ctrl := gomock.NewController(t)
					uStore := mock.NewMockUserStore(ctrl)
					aStore := mock.NewMockAccountStore(ctrl)
					svc := kagi.NewCredentialService(uStore, aStore, fastPasswordConfig(), fakeClk)

					sc.setupMocks(ctrl, uStore, aStore)
					in := sc.input(secret)
					_, err := svc.SignUp(context.Background(), in)
					if err == nil {
						t.Fatal("expected error, got nil")
					}
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("security violation: error message leaked plain password %q: %v", secret, err)
					}
				})
			}
		}
	})
}
