package intelligence

// Provider registrations (CORE) — the open-core free-build half of the
// registry. This file registers ONLY TierCore providers. The TierPremium
// registrations live in internal/intelligence/premium/register.go, whose
// init() calls intelligence.RegisterProvider with the matching Order
// values; that package is blank-imported only by the enterprise build.
//
// Order pinning (the key to a cross-package split):
//
//	Each registration carries an explicit Order that pins its slot in the
//	final provider slice. buildRegisteredProviders sorts by Order, so the
//	historical interleaved sequence is reproduced regardless of whether the
//	premium package's init() ran before or after this one. The canonical
//	Order map (0..40) is the pre-split buildProviders sequence:
//
//	   0  malware            CORE
//	   1  typosquat          CORE
//	   2  provenance         CORE
//	   3  cve                CORE
//	   4  metadiff           PREMIUM
//	   5  publishvelocity    PREMIUM
//	   6  reservedns         CORE
//	   7  osv                CORE
//	   8  registrymetadata   CORE
//	   9  installscripts     CORE
//	  10  hiddenunicode      CORE
//	  11  checksum           CORE
//	  12  shrinkwrap         CORE
//	  13  manifestconfusion  CORE (npm)
//	  14  manifestconfusion  CORE (pypi)
//	  15..23 codesmell       PREMIUM
//	  24..25 wave4_artifact  PREMIUM
//	  26..27 wave4_rtt       PREMIUM
//	  28  wave4_maintainer_age PREMIUM
//	  29..31 aiartifact      PREMIUM
//	  32  capability         PREMIUM
//	  33  weeklyDownloads    PREMIUM
//	  34  kev                CORE
//	  35  firsttimecollaborator PREMIUM
//	  36  repolink           CORE
//	  37  agenttool_verify   PREMIUM
//	  38  signature_verify   CORE
//	  39  maintenance        PREMIUM
//	  40  pubwithdrawal      PREMIUM
//
// The nil-returning closures reproduce the old `if cfg.X != nil` guards: a
// nil result is skipped order-preservingly by buildRegisteredProviders.

func init() { registerCoreProvidersInOrder() }

// registerCoreProvidersInOrder registers every TierCore provider with its
// canonical Order. PREMIUM Orders (4, 5, 15-33, 35, 37, 39, 40) are owned
// by internal/intelligence/premium.
func registerCoreProvidersInOrder() {
	// ---- Tier-1 (metadata-only, fan out in parallel) ----

	// CORE: malware lookup. Skipped when no index is wired.
	RegisterProvider(ProviderRegistration{
		Name: "malware", Tier: TierCore, Order: 0,
		Factory: func(cfg BootstrapConfig) Provider {
			if cfg.MalwareIndex == nil {
				return nil
			}
			return newMalwareProvider(cfg.MalwareIndex)
		},
	})
	// CORE: typosquat BK-tree matcher. Skipped when no detector is wired.
	RegisterProvider(ProviderRegistration{
		Name: "typosquat", Tier: TierCore, Order: 1,
		Factory: func(cfg BootstrapConfig) Provider {
			if cfg.TyposquatDetector == nil {
				return nil
			}
			return newTyposquatProvider(cfg.TyposquatDetector)
		},
	})
	// CORE: provenance checker. Skipped when no checker is wired.
	RegisterProvider(ProviderRegistration{
		Name: "provenance", Tier: TierCore, Order: 2,
		Factory: func(cfg BootstrapConfig) Provider {
			if cfg.ProvenanceChecker == nil {
				return nil
			}
			return newProvenanceProvider(cfg.ProvenanceChecker)
		},
	})
	// CORE: CVE cross-reference. Skipped when no metadata store is wired.
	RegisterProvider(ProviderRegistration{
		Name: "cve", Tier: TierCore, Order: 3,
		Factory: func(cfg BootstrapConfig) Provider {
			if cfg.MetadataStore == nil {
				return nil
			}
			return newCVEProvider(cfg.MetadataStore)
		},
	})
	// (Order 4 metadiff, Order 5 publishvelocity — PREMIUM, see premium pkg.)

	// CORE: reserved namespaces — pure pattern work, no deps.
	RegisterProvider(ProviderRegistration{
		Name: "reservedns", Tier: TierCore, Order: 6,
		Factory: func(BootstrapConfig) Provider { return newReservedNamespacesProvider() },
	})
	// CORE: OSV bundled vuln provider. Dormant unless the bundle path
	// resolves — see provider_osv.go. Registered unconditionally so the
	// post-build OSV refresher / readiness wiring can still find it.
	RegisterProvider(ProviderRegistration{
		Name: "osv", Tier: TierCore, Order: 7,
		Factory: func(cfg BootstrapConfig) Provider { return newOSVProvider(cfg.Logger) },
	})
	// CORE: registry metadata — runs unconditionally; Supports() gates it.
	RegisterProvider(ProviderRegistration{
		Name: "registrymetadata", Tier: TierCore, Order: 8,
		Factory: func(BootstrapConfig) Provider { return newRegistryMetadataProvider() },
	})

	// ---- Tier-2 (artifact-bound, run in parallel when req.Artifact set) ----

	// CORE: install scripts.
	RegisterProvider(ProviderRegistration{
		Name: "installscripts", Tier: TierCore, Order: 9,
		Factory: func(BootstrapConfig) Provider { return newInstallScriptsProvider() },
	})
	// CORE: hidden unicode.
	RegisterProvider(ProviderRegistration{
		Name: "hiddenunicode", Tier: TierCore, Order: 10,
		Factory: func(BootstrapConfig) Provider { return newHiddenUnicodeProvider() },
	})
	// CORE: checksum.
	RegisterProvider(ProviderRegistration{
		Name: "checksum", Tier: TierCore, Order: 11,
		Factory: func(BootstrapConfig) Provider { return newChecksumProvider() },
	})
	// CORE: shrinkwrap (npm-only tarball-derived).
	RegisterProvider(ProviderRegistration{
		Name: "shrinkwrap", Tier: TierCore, Order: 12,
		Factory: func(BootstrapConfig) Provider { return newShrinkwrapProvider() },
	})
	// CORE: manifest confusion (npm + PyPI variants form one logical unit).
	RegisterProvider(ProviderRegistration{
		Name: "manifestconfusion", Tier: TierCore, Order: 13,
		Factory: func(BootstrapConfig) Provider { return newManifestConfusionProvider() },
	})
	RegisterProvider(ProviderRegistration{
		Name: "manifestconfusion", Tier: TierCore, Order: 14,
		Factory: func(BootstrapConfig) Provider { return newPyPIManifestConfusionProvider() },
	})

	// (Order 15..33 — PREMIUM Tier-2 block: codesmell, wave4_artifact,
	// wave4_rtt, wave4_maintainer_age, aiartifact, capability,
	// weeklyDownloads. See internal/intelligence/premium.)

	// ---- Tier-3 (post-merge) ----

	// CORE: KEV cross-reference. Skipped when no KEV index is wired.
	RegisterProvider(ProviderRegistration{
		Name: "kev", Tier: TierCore, Order: 34,
		Factory: func(cfg BootstrapConfig) Provider {
			if cfg.KEVIndex == nil {
				return nil
			}
			return newKEVProvider(cfg.KEVIndex)
		},
	})
	// (Order 35 firsttimecollaborator — PREMIUM, see premium pkg.)

	// CORE: repo-link liveness probe. A nil checker disables the probe but
	// the provider is still registered (it degrades gracefully).
	RegisterProvider(ProviderRegistration{
		Name: "repolink", Tier: TierCore, Order: 36,
		Factory: func(cfg BootstrapConfig) Provider {
			var checker repoLivenessClassifier
			if cfg.RepoLiveness != nil {
				checker = cfg.RepoLiveness
			}
			return newRepolinkProvider(checker)
		},
	})
	// (Order 37 agenttool_verify — PREMIUM, see premium pkg.)

	// CORE: signature-verify enricher (Tier-3 projection).
	RegisterProvider(ProviderRegistration{
		Name: "signature_verify", Tier: TierCore, Order: 38,
		Factory: func(BootstrapConfig) Provider { return newSignatureVerifyProvider() },
	})

	// (Order 39 maintenance, Order 40 pubwithdrawal — PREMIUM Tier-4 block.
	// See internal/intelligence/premium.)
}
