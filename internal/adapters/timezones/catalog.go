package timezones

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"regexp"
	"time"

	"github.com/JustIkra/umir-auth/internal/application"
)

var zoneName = regexp.MustCompile(`^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$`)

type Catalog struct {
	zones map[string]*time.Location
	data  application.ZoneData
}

func New(data []byte, version string) (*Catalog, error) {
	if len(data) == 0 || len(data) > 16<<20 || version == "" || len(version) > 128 {
		return nil, application.ErrTimeZoneDataUnavailable
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, application.ErrTimeZoneDataUnavailable
	}
	if len(r.File) == 0 || len(r.File) > 2048 {
		return nil, application.ErrTimeZoneDataUnavailable
	}
	c := &Catalog{zones: map[string]*time.Location{}, data: application.ZoneData{Version: version}}
	sum := sha256.Sum256(data)
	c.data.SHA256 = hex.EncodeToString(sum[:])
	var total int
	for _, f := range r.File {
		if !zoneName.MatchString(f.Name) || f.Name == "Local" || f.UncompressedSize64 > 1<<20 {
			return nil, application.ErrTimeZoneDataUnavailable
		}
		if _, ok := c.zones[f.Name]; ok {
			return nil, application.ErrTimeZoneDataUnavailable
		}
		stream, err := f.Open()
		if err != nil {
			return nil, application.ErrTimeZoneDataUnavailable
		}
		b, readErr := io.ReadAll(io.LimitReader(stream, (1<<20)+1))
		closeErr := stream.Close()
		if readErr != nil || closeErr != nil || len(b) > 1<<20 {
			return nil, application.ErrTimeZoneDataUnavailable
		}
		total += len(b)
		if total > 16<<20 {
			return nil, application.ErrTimeZoneDataUnavailable
		}
		loc, err := time.LoadLocationFromTZData(f.Name, b)
		if err != nil {
			return nil, application.ErrTimeZoneDataUnavailable
		}
		c.zones[f.Name] = loc
	}
	if _, ok := c.zones["Europe/Moscow"]; !ok {
		return nil, application.ErrTimeZoneDataUnavailable
	}
	return c, nil
}
func (c *Catalog) Ready() (application.ZoneData, error) {
	if c == nil || len(c.zones) == 0 {
		return application.ZoneData{}, application.ErrTimeZoneDataUnavailable
	}
	return c.data, nil
}
func (c *Catalog) Validate(zone string) error {
	if _, err := c.Ready(); err != nil {
		return err
	}
	if _, ok := c.zones[zone]; !ok {
		return application.ErrUnknownTimeZone
	}
	return nil
}
