package bootstrap

import (
	"context"
	"errors"
	"os"

	"github.com/JustIkra/umir-auth/internal/adapters/password"
	"github.com/JustIkra/umir-auth/internal/domain"
)

func OpenImported(ctx context.Context, o Options, imported domain.ValidatedAggregate) (*Runtime, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	for _, path := range []string{o.StateFile, o.SecretsDir} {
		if _, e := os.Lstat(path); !errors.Is(e, os.ErrNotExist) {
			return nil, ErrBootstrapConflict
		}
	}
	return open(ctx, o, &imported)
}
func validateImported(o Options, imported domain.ValidatedAggregate, checker *password.Hasher) (domain.ValidatedAggregate, error) {
	v, e := domain.Validate(imported.Snapshot())
	if e != nil {
		return domain.ValidatedAggregate{}, ErrBootstrapConflict
	}
	found := false
	for _, u := range v.Snapshot().Users {
		if u.UserID == o.Initial.UserID {
			if u.Login != o.Initial.Login || u.DisplayName != o.Initial.DisplayName || u.CredentialVersion != o.Initial.CredentialVersion || u.Email != o.Initial.Email || checker.Check(u.Verifier) != nil {
				return domain.ValidatedAggregate{}, ErrBootstrapConflict
			}
			found = true
		}
	}
	if !found {
		return domain.ValidatedAggregate{}, ErrBootstrapConflict
	}
	return v, nil
}
