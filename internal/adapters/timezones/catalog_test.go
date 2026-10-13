package timezones_test

import (
	"errors"
	"os"

	"testing"

	"github.com/JustIkra/umir-auth/internal/adapters/timezones"
	"github.com/JustIkra/umir-auth/internal/application"
)

func TestExplicitPackagedDataFailsClosed(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("not zip")} {
		if _, e := timezones.New(data, "known"); !errors.Is(e, application.ErrTimeZoneDataUnavailable) {
			t.Fatal("absent/corrupt data accepted")
		}
	}
	b, e := os.ReadFile("../../../tests/testdata/zoneinfo.zip")
	if e != nil {
		t.Fatal(e)
	}
	c, e := timezones.New(b, "go1.26.9-packaged")
	if e != nil {
		t.Fatal(e)
	}
	info, e := c.Ready()
	if e != nil || info.Version != "go1.26.9-packaged" || len(info.SHA256) != 64 {
		t.Fatal("packaged identity absent")
	}
	for _, zone := range []string{"Europe/Moscow", "America/New_York", "Asia/Tokyo"} {
		if e := c.Validate(zone); e != nil {
			t.Fatal(e)
		}
	}
	for _, zone := range []string{"Local", "", "Unknown/Zone", "../Europe/Moscow"} {
		if !errors.Is(c.Validate(zone), application.ErrUnknownTimeZone) {
			t.Fatal("unknown/host zone fallback")
		}
	}
	b[0] ^= 1
	if e := c.Validate("Europe/Moscow"); e != nil {
		t.Fatal("retained input mutated catalog")
	}
}
