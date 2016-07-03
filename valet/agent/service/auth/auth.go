// Package auth provides access to authentication information for users to access devices.
// Varying methods can be added over time to fit the needs of different organizations.
package auth

import (
  "golang.org/x/crypto/ssh"
)

// Any is used to indicate that the auth information can be used for any device.
// More specific always overrides Any.
const Any = "any"

var registry Storage

// Register registers storage locations starting with "marker" with "store".
func Register(store Storage) {
  if registry != nil {
    panic("an authenication store was already registered")
  }

  registry = store
}

// Data contains the necessary authorization data to use for the user/device combination.
type Data struct {
  // Key is some type of authentication key that can be used for this user on the device.
  Key ssh.Signer

  // Password is a password that can be used by user on the device.
  Password string
}

// Retrieve retrieves from a storage location the authentication data needed for a router.
func Retrieve(user, device string) (Data, error) {
  return registry.Retrieve(user, device)
}

// Storage provides some type of storage mechansim for holding user/key/password data for
// accessing a network device.
type Storage interface {
  Retrieve(user, device string) (Data, error)
}
