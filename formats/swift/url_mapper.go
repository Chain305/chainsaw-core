package swift

import (
	"net/url"

	"github.com/chain305/chainsaw-core/proxy"
)

// NewRemoteURLMapper returns a RemoteURLMapper for the Swift registry.
//
// SPM logical paths are 1:1 with SE-0292 endpoint paths on the upstream
// (no rewriting like cargo's crates.io download split). The mapper
// returns nil for every path so the facet uses defaultBase + logicalPath.
//
// The constructor is kept so the builder wiring mirrors other formats;
// if SPM adds sidecar artifacts on a separate host in a future spec
// version, this is where we would handle them.
func NewRemoteURLMapper(_ *url.URL) proxy.RemoteURLMapper {
	return func(_ string, _ *url.URL) *proxy.RemoteURLMapping {
		return nil
	}
}
