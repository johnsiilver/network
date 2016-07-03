package etoe

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
  "os/exec"
  "os/user"
	"net"
  "strings"
	"testing"

	"github.com/johnsiilver/network/valet/agent/instance"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	log "github.com/golang/glog"
	apb "github.com/johnsiilver/network/valet/agent/proto/agent"
)

const agentPort = 6523

func initService() {
	f := instance.Flags{
		Port: agentPort,
		Cert: instance.Cert{
			CRT: "test_files/cert.pem",
			Key: "test_files/key.pem",
		},
		FrontendCerts: []string{},
		AuthFile:      "test_files/auth.json",
		ConfigPath:    "test_files/config.json",
	}

	go func() {
		if err := instance.Serve(f); err != nil {
			panic(err)
		}
	}()

	//ready := PassDevice()
  ready := make(chan struct{})
  go server2(ready)
	<-ready
  log.Infof("finished init")
}

func server2(ready chan struct{})  {
  config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if c.User() == "user0" && string(pass) == "pass" {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}
	privateBytes, err := ioutil.ReadFile("test_files/id_rsa")
	if err != nil {
		panic("Failed to load private key")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		panic("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:1865")
	if err != nil {
		log.Fatalf("Failed to listen: %s", err)
	}

	// Accept all connections
	log.Infof("Listening on 1865...")
  close(ready)
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Errorf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Errorf("Failed to handshake (%s)", err)
			continue
		}

		log.Infof("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
    panic("blah")
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Errorf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "exec"
  // We just want to handle "exec".
	go func() {
		for req := range requests {
			switch req.Type {
      case "exec":
        var reqCmd struct{ Text string }
        if err := ssh.Unmarshal(req.Payload, &reqCmd); err != nil {
            panic(err)
        }
        log.Infof("server: got command: %q\n", reqCmd.Text)
        cmd := exec.Command(reqCmd.Text)
        cmd.Stdout = channel
        cmd.Stderr = channel.Stderr()
        err := cmd.Run()
        if err != nil {
            panic(err)
        }

        if req.WantReply {
            // no special payload for this reply
            req.Reply(true, nil) // or false if the command failed to run successfully
        }
        if _, err := channel.SendRequest("exit-status", false, []byte{0, 0, 0, 0}); err != nil {
            panic(err)
        }

        if err := channel.Close(); err != nil {
            panic(err)
        }
      default:
        panic(req.Type)
			}
		}
	}()
}

func Test(t *testing.T) {
  initService()
	config := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := grpc.Dial(fmt.Sprintf("0.0.0.0:%d", agentPort), grpc.WithTransportCredentials(credentials.NewTLS(config)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	client := apb.NewAgentServiceClient(conn)
	rc, err := client.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	rc.Send(
		&apb.CmdReq{
			Device:  "passDevice",
			User:    "user0",
			Cmd:     "/usr/bin/whoami",
			CmdType: apb.CmdReq_READ,
		},
	)
	resp, err := rc.Recv()
	if err != nil {
		t.Fatal(err)
	}

  u, err := user.Current()
  if err != nil {
    panic(err)
  }
  if strings.TrimSpace(resp.Output) != u.Username {
    t.Fatalf("got %q, want %q", resp.Output, u.Username)
  }
}
