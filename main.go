package main

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/bitrise-io/go-steputils/cache"
	"github.com/bitrise-io/go-steputils/tools"
	"github.com/bitrise-io/go-steputils/v2/stepconf"
	"github.com/bitrise-io/go-utils/v2/command"
	"github.com/bitrise-io/go-utils/v2/env"
	"github.com/bitrise-io/go-utils/v2/log"
	"github.com/bitrise-io/go-utils/v2/log/colorstring"
)

type Report struct {
	ReportType   string
	FileName     string
	OutputEnvVar string
}

var reportFormats []Report = []Report{
	Report{"HTML", "dependency-check-report.html", "DEPENDENCY_CHECK_HTML_REPORT_PATH"},
	Report{"XML", "dependency-check-report.xml", "DEPENDENCY_CHECK_XML_REPORT_PATH"},
	Report{"CSV", "dependency-check-report.csv", "DEPENDENCY_CHECK_CSV_REPORT_PATH"},
	Report{"JSON", "dependency-check-report.json", "DEPENDENCY_CHECK_JSON_REPORT_PATH"},
	Report{"JUNIT", "dependency-check-junit.xml", "DEPENDENCY_CHECK_JUNIT_REPORT_PATH"},
	Report{"SARIF", "dependency-check-report.sarif", "DEPENDENCY_CHECK_SARIF_REPORT_PATH"},
}

var validReportFormats []string = []string{
	"HTML",
	"XML",
	"CSV",
	"JSON",
	"JUNIT",
	"SARIF",
	"ALL",
}

// Config ...
type Config struct {
	Debug bool `env:"debug"`

	OutputDirectory string `env:"output_path"`
	ProjectName     string `env:"project_name"`
	ScanPath        string `env:"scan_path,required"`
	SuppressionFile string `env:"suppression_file"`

	FailOnCVSS                   string `env:"fail_on_cvss,range[0..10]"`
	FailStepIfVulnFound          bool   `env:"fail_step_if_vulnerability_found"`
	EnabledExperimentalAnalyzers bool   `env:"enable_experimetnal_analyzers"`

	CacheVulnDatabase bool   `env:"cache_database"`
	VulnDatabasePath  string `env:"data_path"`

	ReportFormats []string `env:"report_formats,required"`
}

type RunOutput struct {
}

type Step struct {
	commandFactory command.Factory
	inputParser    stepconf.InputParser
	logger         log.Logger
}

type CommandMapper func(string) string

func main() {

	var config Config
	envRepository := env.NewRepository()

	// this steps runtime state
	step := Step{
		commandFactory: command.NewFactory(envRepository),
		inputParser:    stepconf.NewInputParser(envRepository),
		logger:         log.NewLogger(),
	}

	if err := step.inputParser.Parse(&config); err != nil {
		step.logger.Errorf("Configuration error: %s\n", err)
		os.Exit(7)
	}

	step.logger.EnableDebugLog(config.Debug)

	stepconf.Print(config)

	exitCode, runErr := step.RunStep(config)
	if runErr != nil {
		step.logger.Errorf(runErr.Error())
		os.Exit(1)
	} else {
		os.Exit(exitCode)
	}

}

type DependencyCheckerArgs struct {
	args []string
}

func (dpArgs *DependencyCheckerArgs) addArg(value ...string) {
	dpArgs.args = append(dpArgs.args, value...)
}

func (step Step) RunStep(config Config) (int, error) {

	var dpArgs = DependencyCheckerArgs{}

	dpArgs.addArg("--project", config.ProjectName)
	dpArgs.addArg("--scan", config.ScanPath)

	if config.EnabledExperimentalAnalyzers {
		dpArgs.addArg("--enableExperimental")
	}

	if config.FailOnCVSS != "" {
		dpArgs.addArg("--failOnCVSS", config.FailOnCVSS)
	}

	if config.SuppressionFile != "" {
		dpArgs.addArg("--suppression", config.SuppressionFile)
	}

	vulnDatabasePath, err := filepath.Abs(config.VulnDatabasePath)
	if err == nil {
		dpArgs.addArg("--data", vulnDatabasePath)
	} else {
		step.logger.Errorf("Could not locate path to persist the vulnerability database. Error: %s", err)
	}

	var outputDir string
	if config.OutputDirectory != "" {
		if filepath.IsAbs(config.OutputDirectory) {
			outputDir = config.OutputDirectory
		} else {
			outputDir, _ = filepath.Abs(config.OutputDirectory)
		}
	} else {
		outputDir = filepath.Base("")
	}

	dpArgs.addArg("--out", outputDir)

	if len(config.ReportFormats) > 0 {
		for _, reportFormat := range config.ReportFormats {
			if reportFormat == "" {
				// just skip empty entries
				continue
			}
			if slices.Contains(validReportFormats, reportFormat) {
				dpArgs.addArg("--format", reportFormat)
			} else {
				step.logger.Warnf("%s is not a valid report type for dependency check and will not be generated")
			}
		}
	} else {
		step.logger.Errorf("No report formats in input")
		os.Exit(1)
	}

	cmdOpts := command.Opts{
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	//.SetStdout(os.Stdout).SetStderr(os.Stderr)
	cmd := step.commandFactory.Create("dependency-check", dpArgs.args, &cmdOpts)

	step.logger.Infof("Running dependency-check %s", strings.Join(dpArgs.args, " "))

	exitCode, err := cmd.RunAndReturnExitCode()

	if err != nil {
		step.logger.Errorf("Failed to expose output with envman, error: %#v", err)
	}

	step.TryWriteCache(config, vulnDatabasePath)

	// For every defined report format write to the output vars
	// with the file path if the file exists.
	// if the file doesn't exist then the value isn't written and will be empty when used
	for _, reportFormat := range reportFormats {
		reportFilePath, _ := filepath.Abs(filepath.Join(outputDir, reportFormat.FileName))
		_, err := os.Stat(reportFilePath)
		if err == nil {
			step.logger.Infof("%s report is now available in the environment variable %s", reportFormat.ReportType, reportFormat.OutputEnvVar)
			tools.ExportEnvironmentWithEnvman(reportFormat.OutputEnvVar, reportFilePath)
		}
	}

	if config.FailStepIfVulnFound {
		return exitCode, nil
	} else {
		return 0, nil
	}
}

func (step Step) TryWriteCache(config Config, vulnDatabasePath string) {
	// Create cache
	if config.CacheVulnDatabase {
		step.logger.Println()
		step.logger.Infof("Collecting dependency check vulnerability database")

		dpCache := cache.New()
		dpCache.IncludePath(vulnDatabasePath)

		if err := dpCache.Commit(); err != nil {
			step.logger.Warnf("Cache collection skipped: %s", err)
		} else {
			step.logger.Donef("Cache path added to $BITRISE_CACHE_INCLUDE_PATHS")
			step.logger.Printf("Add '%s' step to upload the collected cache for the next build.", colorstring.Yellow("Bitrise.io Cache:Push"))
		}
	}
}
