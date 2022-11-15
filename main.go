package main

import (
	"fmt"
	"os"
	"os/exec"
	
	"github.com/bitrise-io/go-steputils/v2/stepconf"
)

// Config ...
type Config struct {
	DataPath    	string   `env:"data_path,dir"`
	ProjectName 	string   `env:"project_name"`
	ScanPath 		string   `env:"scan_path,required"`
}

// type argmapping struct {

// 	bitriseName string
// 	valueMapper func (string) string	 // maps the bitrise value to a piece of the command

// }

type CommandMapper func (string) string

func main() {

	var config Config
	if err := stepconf.Parse(&config); err != nil {
		log.Errorf("Configuration error: %s\n", err)
		os.Exit(7)
	}
	stepconf.Print(config)

	argsMap := map[string]CommandMapper{
		Config.DataPath: func (in string) string { 
			return fmt.Sprintf(" --data %s", in)
		},
		Config.ProjectName: func (in string) string { 
			return fmt.Sprintf(" --project %s", in)
		},
		Config.ScanPath: func (in string) string { 
			return fmt.Sprintf(" --scan %s", in)
		},
	}

	commandArgs := []string { 
		"dependency-check",
	}

	// for _, argmapping := range argsMap {
	// 	mappedValue := argmapping.valueMapper("some value")
	// 	if mappedValue != nil {
	// 		append(commandArgs, mappedValue)
	// 	}
	// }

	fmt.Println(commandArgs)

	fmt.Println("This is the value specified for the input 'example_step_input':", os.Getenv("example_step_input"))

	//
	// --- Step Outputs: Export Environment Variables for other Steps:
	// You can export Environment Variables for other Steps with
	//  envman, which is automatically installed by `bitrise setup`.
	// A very simple example:
	cmdLog, err := exec.Command("bitrise", "envman", "add", "--key", "EXAMPLE_STEP_OUTPUT", "--value", "the value you want to share").CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to expose output with envman, error: %#v | output: %s", err, cmdLog)
		os.Exit(1)
	}
	// You can find more usage examples on envman's GitHub page
	//  at: https://github.com/bitrise-io/envman

	//
	// --- Exit codes:
	// The exit code of your Step is very important. If you return
	//  with a 0 exit code `bitrise` will register your Step as "successful".
	// Any non zero exit code will be registered as "failed" by `bitrise`.
	os.Exit(0)
}
