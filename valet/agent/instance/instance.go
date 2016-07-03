package instance

import(
  "crypto/x509"
  "fmt"
  "net"

  "github.com/johnsiilver/golib/filewatcher"
  "github.com/johnsiilver/network/valet/agent/service"
  "google.golang.org/grpc"
  "google.golang.org/grpc/credentials"

  authLocal "github.com/johnsiilver/network/valet/agent/service/auth/local"
  pb "github.com/johnsiilver/network/valet/agent/proto/agent"

  _ "github.com/johnsiilver/golib/filewatcher/local"
)

var (
  pubCerts []*x509.Certificate
  privateCert *x509.Certificate
)

// Cert represents a certificate for the device.
type Cert struct {
  // CRT is the path to the server.crt file.
  CRT string

  // Key is the path to the server.key file.
  Key string
}

type Flags struct {
  // Port is the port to run the server on.
  Port int

  // Cert is the path to X509 certs to use for TLS.
  Cert Cert

  // FrontentCerts are certs that are used to validate we are talking only to the frontends.
  FrontendCerts []string

  // AuttFile is the location of a file containing all the user names and their keys.
  AuthFile string

  // ConfigPath is the path to the configuration file for this agent.
  ConfigPath string

  // Insecure prevents TLS transport security.
  Insecure bool
}

// Validate validates the flags for errors.
func (f Flags) Validate() error {
   if f.Cert.CRT == "" || f.Cert.Key == "" {
     return fmt.Errorf("must provide --cert and --key")
   }

   if f.ConfigPath == "" {
     return fmt.Errorf("--config_file cannot be an empty string")
   }
   return nil
}

// Serve begins serving via GRPC.  This blocks indefinitely if there is not an error.
func Serve(f Flags) error {
  if err := f.Validate(); err != nil {
    return err
  }

  server, err := service.New(filewatcher.Local+f.ConfigPath)
  if err != nil {
    return err
  }

  if err := auth(f); err != nil {
    return err
  }

  lis, err := net.Listen("tcp", fmt.Sprintf(":%d", f.Port))
  if err != nil {
    return err
  }

  var opts []grpc.ServerOption
  creds, err := credentials.NewServerTLSFromFile(f.Cert.CRT, f.Cert.Key)
	if err != nil {
    return fmt.Errorf("problem parsing the credentials: %s", err)
	}
	opts = []grpc.ServerOption{grpc.Creds(creds)}

  grpcServer := grpc.NewServer(opts...)
  pb.RegisterAgentServiceServer(grpcServer, server)

  grpcServer.Serve(lis)
  return nil
}

func auth(f Flags) error {
    if f.AuthFile == "" {
       return fmt.Errorf("--authentication_file cannot be an empty string")
    }

    if err := authLocal.Init(f.AuthFile); err != nil {
      return err
    }
    return nil
}
