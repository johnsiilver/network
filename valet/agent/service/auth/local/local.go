// Package local provides access to a JSON file for device authentication information.
package local

import (
  "encoding/json"
  "fmt"
  "io/ioutil"
  "sync"

  "github.com/johnsiilver/golib/filewatcher"
  "github.com/johnsiilver/network/valet/agent/service/auth"
  "golang.org/x/crypto/ssh"

  log "github.com/golang/glog"
)

// Store represents the JSON datastore for auth information stored on disk.
type Store struct {
  // Authentication information keyed by user.
  Authentication map[string]*Auth
}

func (s *Store) retrieveKeyData() error {
    for userName, user := range s.Authentication {
      for devName, dev := range user.Device {
        if dev.KeyPath == "" {continue}

        b, err := ioutil.ReadFile(dev.KeyPath)
        if err != nil {
          return fmt.Errorf("authenication for user %q, device %q had KeyPath %q that could not be retrieved: %s", userName, devName, dev.KeyPath, err)
        }

        key, err := ssh.ParsePrivateKey(b)
        if err != nil {
          return fmt.Errorf("user %q, device %q, key %q could not be parsed: %s", userName, devName, dev.KeyPath, err)
        }
        dev.keyData = key
      }
    }
    return nil
}

// Auth is the user to device authentication information.
type Auth struct {
  // Device is information for the user to log into a device.  Key's are device names or "any"
  // to indicate that the auth information can be used for any device.
  Device map[string]*Device
}

// Device is the device authentication information.
type Device struct {
  // Password is the login password if the system supports password authentication.
  Password string

  // KeyPath is the path to a key that can be used to log onto the device.
  KeyPath string

  // keyData holds the key's data once it has been loaded from KeyPath.
  keyData ssh.Signer
}

// Key retrieves the key from the filesystem.
func (d *Device) Key() ssh.Signer {
  return d.keyData
}

type local struct {
  fileCh chan []byte
  store *Store
  sync.Mutex
}

// New constructs a new authenication storage from a local file.
func New(file string) (auth.Storage, error) {
  ch, closer, err := filewatcher.Get(filewatcher.Local+file, nil)
  if err != nil {
    return nil, fmt.Errorf("problem retrieving file at %q: %s", file, err)
  }

  s, err := unmarshal(<-ch)
  if err != nil {
    closer()
    return nil, err
  }

  l := &local{fileCh: ch, store: s}
  go l.fileHandler()
  return l, nil
}

func (l *local) Retrieve(user, device string) (auth.Data, error) {
  l.Lock()
  defer l.Unlock()

  u, ok := l.store.Authentication[user]
  if !ok {
    log.Infof("%#v", l.store.Authentication)
    return auth.Data{}, fmt.Errorf("user %q is not present in the authenication store", user)
  }

  if d, ok := u.Device[device]; ok {
    return auth.Data{
      Key: d.Key(),
      Password: d.Password,
    }, nil
  }

  if d, ok := u.Device[auth.Any]; ok {
    return auth.Data{
      Key: d.Key(),
      Password: d.Password,
    }, nil
  }

  return auth.Data{}, fmt.Errorf("user %q did not have an entry for device %q or a catchall key 'any'", user, device)
}

func (l *local) fileHandler() {
  for b := range l.fileCh {
    s, err := unmarshal(b)
    if err != nil {
      log.Errorf("authentication file had error in it: %s", err)
      continue
    }
    l.Lock()
    l.store = s
    l.Unlock()
  }
}

func unmarshal(b []byte) (*Store, error) {
  s := &Store{}
  if err := json.Unmarshal(b, s); err != nil {
    return nil, fmt.Errorf("could not unmarshal the authenication store into Go values: %s", err)
  }

  if err := s.retrieveKeyData(); err != nil {
    return nil, err
  }
  return s, nil
}

// Init is used to register local authentication storage if required.  Should be called from main.
func Init(path string) error {
  s, err := New(path)
  if err != nil {
    return err
  }
  auth.Register(s)
  return nil
}
