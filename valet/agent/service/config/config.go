// Package config holds the agent's configuraiton file structure and validators.
package config

const (
  UnknownTransport = 0
  // SSH indicates to use SSH as the communication protocol to a device.
  SSH Transport = 1
)

const (
  NoTransfer = 0
  // SFTP indicates to use SFTP as the communication protocol to a device.
  SFTP Transfer = 1
)

// Transport is the type of transport medium to use to communicate with the device.
type Transport int

// Transfer is what transfer protocol to use to move files back and forth with the device.
type Transfer int

// File details the structure of the agent's configuration file, stored in JSON.
type File struct {
  Devices []Device
}

// Device details the information needed to talk to a device.
type Device struct {
  // Name is the name of the device.
  Name string  // Required

  // Address is the IP address (IPv4 or IPv6) of the host.  We never use the
  // DNS name of the device, always the address when making the connection.
  // This address is also used in host key validation.
  Address string  // Required

  // Port is the port the device is listening on.
  Port int // Required

  // Transport is the type of transport to use to communicate with the device.
  Transport Transport  // Required

  // Transfer is the type of mechanism to use to transport files to and from
  // the device.
  Transfer Transfer  // Required
}
