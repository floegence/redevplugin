package releasecontract

import "testing"

func FuzzDecodeReleaseContracts(f *testing.F) {
	fixture := newReleaseSigningFixture(f)
	for _, build := range []func() ([]byte, error){
		func() ([]byte, error) { return CanonicalRootDelegation(fixture.Root) },
		func() ([]byte, error) { return CanonicalPackageSignature(fixture.PackageContext, fixture.Package) },
		func() ([]byte, error) { return CanonicalReleaseMetadata(fixture.Metadata) },
		func() ([]byte, error) { return CanonicalSourcePolicy(fixture.Policy) },
		func() ([]byte, error) { return CanonicalSourcePolicyPointer(fixture.PolicyPointer) },
		func() ([]byte, error) { return CanonicalRevocation(fixture.Revocation) },
		func() ([]byte, error) { return CanonicalRevocationPointer(fixture.RevocationPointer) },
	} {
		raw, err := build()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"schema_version":"unknown"} true`))
	f.Add([]byte{0xff})

	f.Fuzz(func(_ *testing.T, raw []byte) {
		_, _ = DecodeRootDelegation(raw)
		_, _ = DecodePackageSignature(raw, fixture.PackageContext)
		_, _ = DecodeReleaseMetadata(raw)
		_, _ = DecodeSourcePolicy(raw)
		_, _ = DecodeSourcePolicyPointer(raw)
		_, _ = DecodeRevocation(raw)
		_, _ = DecodeRevocationPointer(raw)
	})
}
