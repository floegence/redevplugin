package host

import (
	"testing"
	"time"
)

func TestPluginLifecycleLockRegistryAllowsIndependentPlugins(t *testing.T) {
	registry := newPluginLifecycleLockRegistry()
	releaseA, err := registry.acquireWrite("plugin_a")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseA()
	acquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireWrite("plugin_b")
		if acquireErr != nil {
			close(acquired)
			return
		}
		acquired <- release
	}()
	select {
	case release, ok := <-acquired:
		if !ok {
			t.Fatal("acquireWrite(plugin_b) failed")
		}
		release()
	case <-time.After(100 * time.Millisecond):
		t.Fatal("independent plugin lock was blocked")
	}
}

func TestPluginLifecycleLockRegistrySerializesSamePlugin(t *testing.T) {
	registry := newPluginLifecycleLockRegistry()
	releaseWrite, err := registry.acquireWrite("plugin_a")
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan func(), 1)
	go func() {
		release, acquireErr := registry.acquireRead("plugin_a")
		if acquireErr != nil {
			close(acquired)
			return
		}
		acquired <- release
	}()
	select {
	case <-acquired:
		t.Fatal("same-plugin read lock acquired while write lock was held")
	case <-time.After(20 * time.Millisecond):
	}
	releaseWrite()
	select {
	case release, ok := <-acquired:
		if !ok {
			t.Fatal("acquireRead(plugin_a) failed")
		}
		release()
	case <-time.After(100 * time.Millisecond):
		t.Fatal("same-plugin read lock did not acquire after write release")
	}
}
