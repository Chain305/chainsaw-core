package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestPostScanChunked: a large lockfile must go out as bounded requests (the
// edge drops any response slower than 120s, and the server's time grows with
// the package count), with the answers merged in order and a failed chunk
// failing the whole scan rather than reading as a shorter, clean lockfile.
func TestPostScanChunked(t *testing.T) {
	var sizes []int
	failOn := -1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Packages []scanPkg `json:"packages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(req.Packages))
		if len(sizes)-1 == failOn {
			http.Error(w, "timeout", 524)
			return
		}
		resp := scanAPIResponse{Total: len(req.Packages), Unscanned: 1, Vulnerable: 2}
		for _, p := range req.Packages {
			resp.Results = append(resp.Results, scanResultItem{Name: p.Name, Version: p.Version, Status: "safe"})
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	configureScan(t, srv.URL)

	pkgs := make([]scanPkg, 250)
	for i := range pkgs {
		pkgs[i] = scanPkg{Name: fmt.Sprintf("crate-%03d", i), Version: "1.0.0", Ecosystem: "cargo"}
	}

	var out scanAPIResponse
	if err := postScanChunked(newClientWithTimeout(time.Minute), pkgs, &out); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sizes) != "[100 100 50]" {
		t.Fatalf("chunk sizes = %v, want [100 100 50]", sizes)
	}
	if len(out.Results) != 250 || out.Results[0].Name != "crate-000" || out.Results[249].Name != "crate-249" {
		t.Fatalf("results not merged in order: n=%d", len(out.Results))
	}
	if out.Total != 250 || out.Unscanned != 3 || out.Vulnerable != 6 {
		t.Fatalf("counters not summed: %+v", out)
	}

	sizes, failOn = nil, 1
	if err := postScanChunked(newClientWithTimeout(time.Minute), pkgs, &scanAPIResponse{}); err == nil {
		t.Fatal("a failed chunk must fail the scan")
	}
}
