package main

import (
	"os"

	"github.com/kysee/zkp/zk-beacon/relayer"
	"github.com/kysee/zkp/zk-beacon/relayer/types"
)

func main() {
	//relayer.RelayerMain(types.NewConfig(os.Args...))

	relayer.ListenerMain(types.NewConfig(os.Args...))
}
