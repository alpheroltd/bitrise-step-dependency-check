# OWASP Dependency Check

Runs the [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) tool to identify depepdancies and potential security vulnerabilities.

# Quick start

Add this step directly to your bitrise workflow.

1. Configure the scan path to the folders you want to scan, by default this scans all files and folders in the relative path.
1. Pick a CVSS score threshold if you want the step to fail if a severe enough vulnerability was found. 
1. Pick the report formats your would like.
1. Specify where to write these reports, defaults to `$BITRISE_DEPLOY_DIR`
