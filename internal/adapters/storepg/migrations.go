package storepg

import (
	"context"
	"embed"
	"errors"
	"fmt"

	"github.com/JustIkra/umir-auth/internal/adapters/postgres"
	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrations embed.FS

func MigrationSpec() postgres.Spec {
	return postgres.Spec{Service: "auth", FS: migrations, Dir: "migrations"}
}

func Generation(ctx context.Context, db *postgres.DB) (string, error) {
	var generation string
	err := db.InSystemTx(ctx, "auth.generation.read", pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT generation::text FROM storage_meta WHERE singleton`).Scan(&generation)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("storage generation is missing")
	}
	if err != nil {
		return "", fmt.Errorf("read storage generation: %w", err)
	}
	return generation, nil
}
