package intelligence

import (
	"reflect"
	"testing"
)

// scanSectionEmpty decides whether Upsert keeps the PRIOR row's whole Scan
// subtree, so a signal-bearing field it does not check can be overwritten
// by stale data. It is a hand-maintained list, and every new
// ArtifactScanSection field has to be remembered there. This test makes
// forgetting fail: each exported field, set alone, must make the section
// non-empty, unless it is listed below with its reason.

// scanEmptyHousekeeping are diagnostic fields that carry no finding.
var scanEmptyHousekeeping = map[string]string{
	"ManifestFilesSeen": "which manifest files the walk saw; diagnostics only",
	"ExtraFindings":     "free-form diagnostic bag; no signal reads it",
}

// scanEmptyDetail are fields only ever written together with a primary field.
// The primary carries the emptiness decision, and the test checks that the
// primary itself is covered.
var scanEmptyDetail = map[string]string{
	"InstallScriptDetector":   "InstallScriptKind",
	"ImportTimeKind":          "ImportTimeExecution",
	"ImportTimeDetail":        "ImportTimeExecution",
	"MaliciousIOCKind":        "MaliciousIOC",
	"MaliciousIOCDetail":      "MaliciousIOC",
	"MaliciousIOCCoupled":     "MaliciousIOC",
	"MaliciousIOCAtEntry":     "MaliciousIOC",
	"BuildRsPrimitives":       "BuildRsExecutes",
	"ManifestConfusionFields": "ManifestConfusion",
	"URLStringsFiles":         "URLStrings",
	"URLStringsSamples":       "URLStrings",
	"DebugAccessSamples":      "DebugAccess",
	"TelemetrySamples":        "Telemetry",
	"DynamicRequireSamples":   "DynamicRequire",
	"LicenseFileExpression":   "LicenseFilePaths",
	"TrivialPackageLOC":       "TrivialPackage",
	"TooManyFilesCount":       "TooManyFiles",
	"MaintainerAge":           "MaintainerAccountAgeDays",
	"DangerousPickleFiles":    "DangerousPickleOpcode",
	"DangerousPickleSummary":  "DangerousPickleOpcode",
	"ModelCardKinds":          "ModelCardInjection",
	"AgentToolCapabilities":   "AgentToolDangerousCapability",
	"ContainerScanNote":       "ContainerScanIncomplete",
}

// setNonZero gives field i of v a non-zero value.
func setNonZero(t *testing.T, v reflect.Value, i int) {
	t.Helper()
	fv := v.Field(i)
	switch fv.Kind() {
	case reflect.Bool:
		fv.SetBool(true)
	case reflect.String:
		fv.SetString("x")
	case reflect.Int, reflect.Int32, reflect.Int64:
		fv.SetInt(1)
	case reflect.Float32, reflect.Float64:
		fv.SetFloat(1)
	case reflect.Slice:
		fv.Set(reflect.MakeSlice(fv.Type(), 1, 1))
	case reflect.Map:
		fv.Set(reflect.MakeMap(fv.Type()))
		fv.SetMapIndex(reflect.New(fv.Type().Key()).Elem(), reflect.New(fv.Type().Elem()).Elem())
	case reflect.Pointer:
		fv.Set(reflect.New(fv.Type().Elem()))
	default:
		t.Fatalf("ArtifactScanSection.%s has kind %s; teach setNonZero about it", v.Type().Field(i).Name, fv.Kind())
	}
}

func onlyField(t *testing.T, name string) ArtifactScanSection {
	t.Helper()
	v := reflect.New(reflect.TypeOf(ArtifactScanSection{})).Elem()
	f, ok := v.Type().FieldByName(name)
	if !ok {
		t.Fatalf("ArtifactScanSection has no field %q — stale entry in an allow-list", name)
	}
	setNonZero(t, v, f.Index[0])
	return v.Interface().(ArtifactScanSection)
}

func TestScanSectionEmptyCoversEveryField(t *testing.T) {
	typ := reflect.TypeOf(ArtifactScanSection{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !typ.Field(i).IsExported() {
			continue
		}
		empty := scanSectionEmpty(onlyField(t, name))
		if _, ok := scanEmptyHousekeeping[name]; ok {
			continue
		}
		if primary, ok := scanEmptyDetail[name]; ok {
			if scanSectionEmpty(onlyField(t, primary)) {
				t.Errorf("%s is allow-listed as detail of %s, but scanSectionEmpty does not check %s either", name, primary, primary)
			}
			continue
		}
		if empty {
			t.Errorf("ArtifactScanSection.%s set alone reads as an EMPTY section, so Upsert would keep the prior row's "+
				"Scan subtree and drop it. Add it to scanSectionEmpty, or list it here as housekeeping or as detail "+
				"of a checked field, with the reason.", name)
		}
	}
}
