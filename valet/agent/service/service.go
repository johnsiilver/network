// Package service contains the golang implementation of the GRPC service for accessing network devices.
package service

import (
  "bytes"
  "encoding/json"
  "fmt"
  "io"
  "sync"

  "github.com/johnsiilver/golib/filewatcher"
  "github.com/johnsiilver/network/valet/agent/service/auth"
  "github.com/johnsiilver/network/valet/agent/service/config"
  "github.com/johnsiilver/network/valet/agent/service/ssh"
  "golang.org/x/net/context"

  log "github.com/golang/glog"
  apb "github.com/johnsiilver/network/valet/agent/proto/agent"
)

// Service implements apb.AgentServiceInterface.
type Service struct {
  confCh chan []byte
  conf map[string]config.Device
  confMu sync.Mutex

  // ssh has keys that are device names to values that are the transport to communicate to the device with.
  ssh map[string]*ssh.Transport
  sshMu sync.Mutex
}

// New is the constructor for Service.
func New(configPath string) (apb.AgentServiceServer, error) {
  ch, closer, err := filewatcher.Get(configPath, nil)
  if err != nil {
    return nil, err
  }

  b := <-ch
  serv := &Service{confCh: ch,}
  if err := serv.handleChange(b); err != nil {
    closer()
    return nil, err
  }
  go serv.confWatcher()
  return serv, nil
}

// confWatcher is meant to be started as a goroutine that watches our configuration file in the background
// for changes.
func (s *Service) confWatcher() {
  for b := range s.confCh {
    s.handleChange(b)
  }
}

// handleChange handles the file content change of our device configuration.
func (s *Service) handleChange(b []byte) error {
  conf := &config.File{}
  if err := json.Unmarshal(b, conf); err != nil {
    log.Errorf("configuration file updated, but new version could not be marshalled into object: %s", err)
  }

  m := make(map[string]config.Device, len(conf.Devices))
  for _, device := range conf.Devices{
    // TODO: Add a validation check to the config.Device info and reject the change if not correct.
    m[device.Name] = device
  }

  s.confMu.Lock()
  defer s.confMu.Unlock()
  s.conf = m
  return nil
}

// RawSession implements apb.AgentServiceServer.RawSession().
func (s *Service) RawSession(stream apb.AgentService_RawSessionServer) error {
  return fmt.Errorf("not implemented")
}
// Run implements apb.AgentServiceServer.run().
func (s *Service) Run(stream apb.AgentService_RunServer) error {
  for {
    in, err := stream.Recv()
    if err == io.EOF {
        return nil
    }
    if err != nil {
        return err
    }

    authData, err := auth.Retrieve(in.User, in.Device)
    if err != nil {
      return err
    }

    var sshOption ssh.Option
    if authData.Key != nil {
        log.Infof("authorizing user %q via SSH key:\n%q", in.User)
        sshOption = ssh.Key(authData.Key)
    }else {
      log.Infof("authorizing user %q via user/pass", in.User)
      sshOption = ssh.UserPass(authData.Password)
    }

    trans, err := s.transport(in.Device)
    if err != nil {
      log.Error(err)
      return err
    }

    session, err := trans.Session(in.User, sshOption)
    if err != nil {
      err = fmt.Errorf("problem creating session to device: %s", err)
      log.Error(err)
      return err
    }
    defer session.Close()

    var b bytes.Buffer
    session.Stdout = &b
    if err := session.Run(in.Cmd); err != nil {
      log.Errorf("problem exeucting Run() on device: %s", err)
      if err := stream.Send(&apb.CmdResp{Output: err.Error()}); err != nil {
        return fmt.Errorf("problem sending RPC response with error: %s", err)
      }
    }else{
      if err := stream.Send(&apb.CmdResp{Output: b.String()}); err != nil {
        return fmt.Errorf("problem sending device output over RPC: %s", err)
      }
    }
  }
}

func (s *Service) transport(d string) (*ssh.Transport, error) {
  s.sshMu.Lock()
  defer s.sshMu.Unlock()

  trans, ok := s.ssh[d]
  if !ok {
    info, ok := s.conf[d]
    if !ok {
      return nil, fmt.Errorf("no device %q is defined in this agent's configuration file", d)
    }
    var err error
    trans, err = ssh.New(d, info.Address, info.Port)
    if err != nil {
      return nil, fmt.Errorf("problem creating transport client for device %q via SSH: %s", d, err)
    }
  }
  return trans, nil
}

// Put implements apb.AgentServiceServer.Put().
func (s *Service) Put(context.Context, *apb.PutReq) (*apb.PutResp, error) {
  return nil, fmt.Errorf("not implemented")
}
// Get implements apb.AgentServiceServer.Put().
func (s *Service) Get(context.Context, *apb.GetReq) (*apb.GetResp, error) {
  return nil, fmt.Errorf("not implemented")
}
