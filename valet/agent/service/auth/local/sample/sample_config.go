package main

import (
  "encoding/json"
  "fmt"

  "github.com/johnsiilver/network/valet/agent/service/auth/local"
)

func main() {
  sample := local.Store{
    Authentication: map[string]*local.Auth{
      "user0": &local.Auth{
        Device: map[string]*local.Device{
          "passDevice": {
            Password: "pass",
          },
        },
      },
    },
  }

  b, err := json.MarshalIndent(sample, "", "\t")
  if err != nil {
    panic(err)
  }

  fmt.Println(string(b))
}
