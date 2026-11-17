package main

import (
	"bytes"
	"fmt"
	"github.com/floegence/redevplugin/v3/pkg/capabilitycontract"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	root, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, e := os.Stat(filepath.Join(root, "VERSION")); e == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			panic("repository root not found")
		}
		root = parent
	}
	for _, artifact := range []struct{ name, directory string }{{"agent-work", "agentwork"}, {"agent-conversation", "agentconversation"}} {
		generate(root, artifact.name, artifact.directory)
	}
}

func generate(root, name, directory string) {
	raw, err := os.ReadFile(filepath.Join(root, "spec/plugin/"+name+"-contract.json"))
	if err != nil {
		panic(err)
	}
	contract, err := capabilitycontract.NewKnownContractFromArtifact(raw)
	if err != nil {
		panic(err)
	}
	client, err := capabilitycontract.GenerateTypeScript(contract.Contract)
	if err != nil {
		panic(err)
	}
	client = []byte(strings.Replace(string(client), "\"@floegence/redevplugin-ui/plugin\"", "\"./plugin.js\"", 1))
	outputs := map[string][]byte{"pkg/" + directory + "/contract.gen.json": raw, "packages/redevplugin-ui/src/" + name + ".gen.ts": client}
	if name == "agent-conversation" {
		retained, err := os.ReadFile(filepath.Join(root, "spec/plugin/agent-conversation-1.0.0-contract.json"))
		if err != nil {
			panic(err)
		}
		if _, err := capabilitycontract.NewKnownContractFromArtifact(retained); err != nil {
			panic(err)
		}
		outputs["pkg/"+directory+"/contract.v1.gen.json"] = retained
	}
	for path, content := range outputs {
		path = filepath.Join(root, path)
		if len(os.Args) > 1 && os.Args[1] == "--check" {
			actual, e := os.ReadFile(path)
			if e != nil || !bytes.Equal(actual, content) {
				panic(fmt.Sprintf("stale generated file: %s", path))
			}
		} else if err = os.WriteFile(path, content, 0644); err != nil {
			panic(err)
		}
	}
}
