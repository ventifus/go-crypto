// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package agent

import (
	"testing"
)

func addTestKey(t *testing.T, a Agent, keyName string) {
	err := a.Add(AddedKey{
		PrivateKey: testPrivateKeys[keyName],
		Comment:    keyName,
	})
	if err != nil {
		t.Errorf("failed to add key '%s': %s", keyName, err)
	}
}

func removeTestKey(t *testing.T, a Agent, keyName string) {
	err := a.Remove(testPublicKeys[keyName])
	if err != nil {
		t.Errorf("failed to remove key '%s': %s", keyName, err)
	}
}

func validateListedKeys(t *testing.T, a Agent, expectedKeys []string) {
	listedKeys, err := a.List()
	if err != nil {
		t.Errorf("failed to list keys: %s", err)
		return
	}
	actualKeys := make(map[string]bool)
	for _, key := range listedKeys {
		actualKeys[key.Comment] = true
	}

	matchedKeys := make(map[string]bool)
	for _, expectedKey := range expectedKeys {
		if !actualKeys[expectedKey] {
			t.Errorf("expected key '%s', but was not found", expectedKey)
		} else {
			matchedKeys[expectedKey] = true
		}
	}

	for actualKey := range actualKeys {
		if !matchedKeys[actualKey] {
			t.Errorf("key '%s' was found, but was not expected", actualKey)
		}
	}
}

func TestKeyringAddingAndRemoving(t *testing.T) {
	keyNames := []string{"dsa", "ecdsa", "rsa", "user"}

	// add all test private keys
	k := NewKeyring()
	for _, keyName := range keyNames {
		addTestKey(t, k, keyName)
	}
	validateListedKeys(t, k, keyNames)

	// remove a key in the middle
	keyToRemove := keyNames[1]
	keyNames = append(keyNames[:1], keyNames[2:]...)

	removeTestKey(t, k, keyToRemove)
	validateListedKeys(t, k, keyNames)

	// remove all keys
	err := k.RemoveAll()
	if err != nil {
		t.Errorf("failed to remove all keys: %s", err)
	}
	validateListedKeys(t, k, []string{})
}
