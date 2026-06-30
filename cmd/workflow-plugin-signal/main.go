package main

import (
	"github.com/GoCodeAlone/workflow-plugin-signal/internal"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewSignalProvider(),
		sdk.WithBuildVersion(sdk.ResolveBuildVersion(internal.Version)),
	)
}
