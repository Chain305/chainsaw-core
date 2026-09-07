package policy

import (
	"reflect"
	"testing"
)

// T2 — regression for DECISION D-CR1: a cooldown is a first-class, standalone
// policy condition. Before this fix hasPolicyCondition omitted CooldownDays, so
// a policy whose ONLY constraint was {cooldownDays: N} was rejected at
// validation time as "no condition".
func TestHasPolicyCondition_CooldownStandalone(t *testing.T) {
	if !hasPolicyCondition(Conditions{CooldownDays: intPtr(7)}) {
		t.Fatal("hasPolicyCondition must return true for a cooldown-only Conditions")
	}
}

// T2 — the actual validator (validatePolicy → hasPolicyConstraint) must accept a
// cooldown-only policy. Cooldown is NOT a context-only signal, so it must not be
// rejected by rejectStandaloneContextOnlyConditions either.
func TestValidatePolicy_AcceptsCooldownOnlyPolicy(t *testing.T) {
	policy := Policy{
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		Conditions: Conditions{CooldownDays: intPtr(7)},
	}
	if err := validatePolicy(policy); err != nil {
		t.Fatalf("cooldown-only policy must validate, got error: %v", err)
	}
}

// T3 (was TestProxyMatrix_CooldownMirrorsPackageAge) — the two publish-age
// columns must NOT move together.
//
// The old assertion was `Support(eco, Cooldown) == Support(eco, PackageAge)`
// for every ecosystem, justified as "both read release-date metadata". That
// was defect N1 written down as an invariant: they read DIFFERENT dates, and
// they are equal only because the proxy was aliasing one into the other.
// Cooldown keys on VersionReleaseDate, which every per-format fetcher
// hydrates and which the hot path backfills from the artifact's
// Last-Modified header. PackageAge keys on PackageReleaseDate, a genuine
// package-creation date that only three registries expose.
//
// This replacement is strictly tighter than the equality it removes: it pins
// each column's exact shape and the direction of the relation, so
// re-collapsing them fails here rather than passing.
func TestProxyMatrix_CooldownAndPackageAgeSupportDiverge(t *testing.T) {
	// The three formats formatSuppliesCreationDate covers
	// (internal/server/package_metadata.go); yarn and bun fold into npm.
	creationDateEcos := map[Ecosystem]bool{EcoNPM: true, EcoPyPI: true, EcoComposer: true}

	for _, eco := range AllEcosystems() {
		age := Support(eco, ConditionPackageAge)
		cool := Support(eco, ConditionCooldown)

		switch {
		case eco == EcoAPT:
			// apt has no arm in either half of the release-date switch.
			if age != SupportNone || cool != SupportNone {
				t.Errorf("apt: want both None, got packageAge=%s cooldown=%s", age, cool)
			}
			continue
		case creationDateEcos[eco]:
			if age != SupportFull {
				t.Errorf("%s: packageAge=%s, want full — this registry DOES expose a "+
					"package-creation date", eco, age)
			}
		default:
			if age != SupportPartial {
				t.Errorf("%s: packageAge=%s, want partial. Full would mean a creation-date "+
					"source appeared (add it to formatSuppliesCreationDate and to "+
					"creationDateEcos above); None is never correct here — IsUnsupported "+
					"is `== SupportNone` and makes detectUnsupported discard the WHOLE "+
					"policy, the P8-16/P8-17 fail-open", eco, age)
			}
		}

		if cool != SupportFull {
			t.Errorf("%s: cooldown=%s, want full — VersionReleaseDate is hydrated on "+
				"every non-apt ecosystem", eco, cool)
		}
		if age == SupportFull && cool != SupportFull {
			t.Errorf("%s: packageAge (%s) outranks cooldown (%s); cooldown's date source "+
				"is a superset, so this is impossible", eco, age, cool)
		}
	}
}

// excludedFromHasPolicyCondition lists Conditions fields that are intentionally
// NOT standalone gates in hasPolicyCondition. Each must carry a reason. The
// exhaustiveness test below treats anything NOT in this set as required.
//
// (Currently empty: every exported Conditions field is a recognised standalone
// condition. The set is kept so that a deliberately-excluded future field has an
// explicit, documented home — and so the next ACCIDENTALLY-dropped condition
// fails CI instead of silently becoming unauthorable, which is exactly the class
// of bug that left CooldownDays unrecognised.)
var excludedFromHasPolicyCondition = map[string]string{}

// C1 — exhaustiveness guard. Walk every exported field of Conditions, build a
// Conditions value with ONLY that field set to a non-zero/non-nil value, and
// assert hasPolicyCondition returns true. A field that is genuinely meant to be
// excluded must be listed (with a reason) in excludedFromHasPolicyCondition.
//
// This is the regression net for the whole class of "a wired condition is not
// recognised as a standalone gate" bug (D-CR1 for cooldown; the SLSA builder
// matchers, MaintainerAccountAge, and the AI-artifact conditions were in the
// same state and are fixed alongside it).
func TestHasPolicyCondition_Exhaustive(t *testing.T) {
	typ := reflect.TypeOf(Conditions{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue // unexported
		}
		if reason, ok := excludedFromHasPolicyCondition[field.Name]; ok {
			if reason == "" {
				t.Errorf("field %s is excluded but carries no reason", field.Name)
			}
			continue
		}

		c := Conditions{}
		setFieldNonZero(t, reflect.ValueOf(&c).Elem().Field(i), field)

		if !hasPolicyCondition(c) {
			t.Errorf("hasPolicyCondition returned false for a Conditions with only %s set; "+
				"either add it to hasPolicyCondition or document it in "+
				"excludedFromHasPolicyCondition with a reason", field.Name)
		}
	}
}

// setFieldNonZero populates a single struct field with a representative non-zero
// value: pointers get a fresh non-zero target, slices get a one-element slice.
// Only the field kinds actually used by Conditions are handled; an unexpected
// kind fails the test so a new field shape can't slip through unverified.
func setFieldNonZero(t *testing.T, v reflect.Value, field reflect.StructField) {
	t.Helper()
	switch v.Kind() {
	case reflect.Ptr:
		elem := reflect.New(v.Type().Elem())
		switch elem.Elem().Kind() {
		case reflect.Bool:
			elem.Elem().SetBool(true)
		case reflect.Int, reflect.Int64:
			elem.Elem().SetInt(1)
		case reflect.Float64:
			elem.Elem().SetFloat(1)
		default:
			t.Fatalf("field %s: unhandled pointer target kind %s", field.Name, elem.Elem().Kind())
		}
		v.Set(elem)
	case reflect.Slice:
		// A meaningful (non-wildcard) single element so hasMeaningfulValues passes.
		if v.Type().Elem().Kind() != reflect.String {
			t.Fatalf("field %s: unhandled slice element kind %s", field.Name, v.Type().Elem().Kind())
		}
		v.Set(reflect.ValueOf([]string{"x"}))
	default:
		t.Fatalf("field %s: unhandled kind %s", field.Name, v.Kind())
	}
}
