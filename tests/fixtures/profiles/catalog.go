package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"

	"github.com/JustIkra/umir-auth/internal/application"
	"github.com/JustIkra/umir-auth/tests/fixtures/protocol"
)

func ObserveCatalog(ctx context.Context, catalog application.TimeZoneCatalog, clock *protocol.Clock) (protocol.ProfileCatalogReport, error) {
	if e := ctx.Err(); e != nil {
		return protocol.ProfileCatalogReport{}, e
	}
	b, e := os.ReadFile("/usr/local/lib/umir/zoneinfo.zip")
	if e != nil {
		return protocol.ProfileCatalogReport{}, e
	}
	fact, e := catalog.Ready()
	if e != nil || fact.SHA256 != protocol.SHA(b) || len(b) == 0 || runtime.Version() != "go1.26.9" {
		return protocol.ProfileCatalogReport{}, errors.New("packaged catalogue mismatch")
	}
	binary, e := protocol.BinarySHA()
	if e != nil {
		return protocol.ProfileCatalogReport{}, e
	}
	provenance, e := json.Marshal(struct {
		BinarySHA256   string `json:"binarySHA256"`
		ArchiveSHA256  string `json:"archiveSHA256"`
		ArchiveBytes   int    `json:"archiveBytes"`
		BuildToolchain string `json:"buildToolchain"`
		Version        string `json:"version"`
	}{binary, fact.SHA256, len(b), runtime.Version(), fact.Version})
	if e != nil {
		return protocol.ProfileCatalogReport{}, e
	}
	return protocol.ProfileCatalogReport{Amendment: protocol.ProfileAmendment, Clock: protocol.ProfileClockRead(clock), InstanceID: clock.Read().InstanceID, BinarySHA256: binary, Catalog: protocol.ProfileCatalogFact{Owner: "auth", Version: fact.Version, ArchiveSHA256: fact.SHA256, ArchiveBytes: len(b), BuildToolchain: runtime.Version(), Ready: true, ProvenanceSHA256: protocol.SHA(provenance)}}, nil
}
