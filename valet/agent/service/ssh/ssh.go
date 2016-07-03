// Package ssh provides the multiplexer for SSH sesssions to a single device.
package ssh

import (
  "fmt"
  "sync"
  "time"

  "golang.org/x/crypto/ssh"
)

type clientOptions struct {
  addr, pass string
  key ssh.Signer
}

// Option is optional arguments to New().
type Option func(s *clientOptions)

// Key indicates to use SSH keys for authentication. This will override UserPass if also provided.
func Key(key ssh.Signer) Option {
  return func(s *clientOptions) {
    s.key = key
  }
}

// UserPass indicates to use user/password for authentication.
func UserPass(pass string) Option {
  return func(s *clientOptions) {
    s.pass = pass
  }
}

// Transport holds SSH connections to a single device.
type Transport struct {
  device, addr string
  port int
  sessions map[string]*ssh.Session
  clients map[string]*ssh.Client
  mu sync.Mutex
}

// New is the constructor for Transport. device is the name of the device, while addr
// is the ipv4 or ipv6 address of the device.
func New(device, addr string, port int) (*Transport, error) {
  return &Transport{
    device: device,
    addr: addr,
    port: port,
    sessions: make(map[string]*ssh.Session, 800),
    clients: make(map[string]*ssh.Client, 100),
  }, nil
}

func (s *Transport) session(user string) (*ssh.Session, bool){
  s.mu.Lock()
  defer s.mu.Unlock()
  sess, ok := s.sessions[user]
  return sess, ok
}

func (s *Transport) client(user string) (*ssh.Client, bool){
  s.mu.Lock()
  defer s.mu.Unlock()
  cli, ok := s.clients[user]
  return cli, ok
}

// connect creates a new connection to the remove system if one does not exist.
func (s *Transport) connect(user string, config *ssh.ClientConfig) (*ssh.Client, error) {
  const sshTimeout = 30 * time.Second

  if v, ok := s.client(user); ok {
    return v, nil
  }

  client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", s.addr, s.port), config)
  if err != nil {
    return nil, err
  }
  s.mu.Lock()
  defer s.mu.Unlock()
  s.clients[user] = client
  return client, nil
}

// session returns a new session for a user or returns one that is already provided.
func (s *Transport) Session (user string, options...Option) (*ssh.Session, error) {
  if len(options) == 0 {
    return nil, fmt.Errorf("Session must be supplied an authentication option")
  }

  if v, ok := s.session(user); ok {
    return v, nil
  }

  opts := &clientOptions{}
  for _, opt := range options {
    opt(opts)
  }

  var auth []ssh.AuthMethod

  if opts.key == nil {
    switch "" {
    case user, opts.pass:
      return nil, fmt.Errorf("no valid authentication methods were provided")
    }
    auth = []ssh.AuthMethod{
      ssh.Password(opts.pass),
      ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
        // Just send the password back for all questions
        answers := make([]string, len(questions))
        for i, _ := range answers {
          answers[i] = opts.pass
        }
        return answers, nil
      }),
    }
  }else{
    auth = []ssh.AuthMethod{ssh.PublicKeys(opts.key)}
  }

  client, err := s.connect(user, &ssh.ClientConfig{User: user, Auth: auth})
  if err != nil {
    return nil, fmt.Errorf("problem making initial connection to host %q: %s", s.device, err)
  }

  session, err := client.NewSession()
  if err != nil {
      return nil, fmt.Errorf("problem creating session to %q: %s", s.device, err)
  }

  s.mu.Lock()
  defer s.mu.Unlock()
  s.sessions[user] = session

  return session, nil
}
