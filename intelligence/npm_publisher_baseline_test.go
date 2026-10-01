package intelligence

import (
	"reflect"
	"testing"
)

func TestNPMPublisherBaseline(t *testing.T) {
	versions := map[string]npmVersionMeta{
		"4.17.21": {NpmUser: &npmHuman{Name: "bnjmnt4n", Email: "benjamin@dev.ofcr.se"}},
		"4.18.0": {
			NpmUser:     &npmHuman{Name: "jdalton", Email: "john.david.dalton@gmail.com"},
			Maintainers: []npmHuman{{Name: "jdalton", Email: "john.david.dalton@gmail.com"}},
		},
		"4.18.1": {NpmUser: &npmHuman{Name: "jdalton", Email: "john.david.dalton@gmail.com"}},
	}
	stamps := map[string]string{
		"created": "2012-04-23T16:37:11.912Z",
		"4.17.21": "2021-02-20T15:42:16.891Z",
		"4.18.0":  "2026-03-31T18:18:42.717Z",
		"4.18.1":  "2026-04-01T21:01:20.458Z",
	}

	// The previous version is chosen by publish time, not by whatever the
	// store touched last.
	got := npmPublisherBaseline(versions, stamps, "4.18.1")
	want := &PublisherBaseline{
		Version:     "4.18.0",
		Publishers:  []string{"jdalton <john.david.dalton@gmail.com>"},
		Maintainers: []string{"jdalton <john.david.dalton@gmail.com>"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("baseline for 4.18.1 = %+v, want %+v", got, want)
	}

	// Maintainers come from the previous version's manifest only. An attacker
	// who adds themselves to the package-level list before publishing must not
	// appear here, or the takeover would vouch for itself.
	if got := npmPublisherBaseline(versions, stamps, "4.18.0"); len(got.Maintainers) != 0 {
		t.Fatalf("4.17.21 manifest lists no maintainers; baseline must not invent any, got %v", got.Maintainers)
	}

	if got := npmPublisherBaseline(versions, stamps, "4.17.21"); got == nil || got.Version != "" {
		t.Fatalf("first version must return an empty baseline, got %+v", got)
	}

	delete(stamps, "4.18.1")
	if got := npmPublisherBaseline(versions, stamps, "4.18.1"); got != nil {
		t.Fatalf("no publish time must return nil so the caller falls back, got %+v", got)
	}
}
