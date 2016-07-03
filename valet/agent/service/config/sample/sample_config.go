package main

import (
  "encoding/json"
  "fmt"

  "github.com/johnsiilver/network/valet/agent/service/config"
)

func main() {
  sample := config.File{
    Devices: []config.Device{
      {
        Name: "test",
        Address: "127.0.0.1:6543",
        Transport: config.SSH,
        Transfer: config.SFTP,
      },
    },
  }

  b, err := json.MarshalIndent(sample, "", "\t")
  if err != nil {
    panic(err)
  }

  fmt.Println(string(b))
}
