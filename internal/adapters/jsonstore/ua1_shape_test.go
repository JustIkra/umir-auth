package jsonstore

import (
	"encoding/json"
	"testing"
)

func TestUA1LegacyRawRejectsNewOptionalFields(t *testing.T) {
	data, err := json.Marshal(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"purpose", "enqueueOrder"} {
		jobs, ok := raw["mailJobs"].([]any)
		if !ok || len(jobs) == 0 {
			t.Fatal("fixture has no jobs")
		}
		job, ok := jobs[0].(map[string]any)
		if !ok {
			t.Fatal("fixture job is not an object")
		}
		job[key] = ""
		bad, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decode(bad); err == nil {
			t.Fatalf("legacy raw accepted new optional field %s", key)
		}
		delete(job, key)
	}
}
