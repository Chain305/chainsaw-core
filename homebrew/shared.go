package homebrew

import (
	"os"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/upstreamhttp"
)

// APIBaseEnv overrides the Homebrew API root for every Chainsaw surface
// (air-gapped mirrors, tests). Unset means DefaultAPIBase.
const APIBaseEnv = "CHAINSAW_HOMEBREW_API_URL"

var (
	sharedOnce   sync.Once
	sharedIndex  *Index
	sharedClient Doer
)

// ConfiguredAPIBase returns the API root honouring APIBaseEnv.
func ConfiguredAPIBase() string {
	if v := strings.TrimSpace(os.Getenv(APIBaseEnv)); v != "" {
		return strings.TrimRight(v, "/")
	}
	return DefaultAPIBase
}

// UserAgent is sent on every formulae.brew.sh request. core/intelligence
// (which imports this package) overwrites it at init with its versioned
// UserAgent("homebrew"); the default keeps the contact URL either way.
var UserAgent = "chainsaw-intelligence (homebrew; +https://chain305.com)"

// SharedClient is the process-wide Homebrew API client: SSRF-guarded and
// charged against the process-wide upstream budget (upstreamhttp.SharedLimiter),
// like every other production upstream client.
func SharedClient() Doer {
	sharedOnce.Do(initShared)
	return sharedClient
}

// SharedIndex is the process-wide formula index. The bottle resolver, the
// registry-metadata provider and the brew.env compiler share it so the 32 MB
// formula.json is held and refreshed once per process.
func SharedIndex() *Index {
	sharedOnce.Do(initShared)
	return sharedIndex
}

func initShared() {
	sharedClient = upstreamhttp.New(upstreamhttp.FromEnv(), upstreamhttp.WithLimiter(upstreamhttp.SharedLimiter())).HTTPClient()
	sharedIndex = NewIndex(IndexConfig{APIBase: ConfiguredAPIBase(), Client: sharedClient})
}
