package rules

// FallbackFix is the text used when a rule has no tailored instruction.
const FallbackFix = "Review the flagged line against the rule description"

// fixes holds the one-line remediation for every built-in rule. The contract
// test fails if a rule id is missing, so this table cannot rot silently.
var fixes = map[string]string{
	"SEC-001":   "Read the Slack token from the environment and rotate the leaked one",
	"SEC-002":   "Read AWS credentials from the default chain and rotate the leaked key",
	"SEC-003":   "Rotate the AWS secret key and load it from the environment",
	"SEC-004":   "Rotate the GCP API key and use application default credentials",
	"SEC-005":   "Delete the service account key file and use workload identity",
	"SEC-006":   "Revoke the GitHub token and read it from a secret store",
	"SEC-007":   "Revoke the npm token and supply it to npmrc from the environment",
	"SEC-008":   "Revoke the PyPI token and inject it only at release time",
	"SEC-009":   "Remove the private key from the tree and load it from a secret manager",
	"SEC-010":   "Move the password to the environment or a secret manager",
	"SEC-011":   "Read the connection string from the environment",
	"SEC-012":   "Load the JWT signing secret from configuration and rotate it",
	"SEC-013":   "Rotate the Azure key and use managed identity",
	"SEC-014":   "Roll the exposed Stripe key and use a restricted key from the environment",
	"SEC-015":   "Roll the Twilio credential and read it from the environment",
	"SEC-016":   "Roll the SendGrid key and read it from the environment",
	"SEC-017":   "Roll the Mailgun key and read it from the environment",
	"SEC-020":   "Use https so the request and its credentials are encrypted",
	"SEC-021":   "Enable certificate verification and remove the skip-verify option",
	"SEC-022":   "Use SHA-256 or stronger instead of MD5",
	"SEC-023":   "Use SHA-256 or stronger instead of SHA-1",
	"SEC-024":   "Use AES-GCM instead of DES or RC4",
	"SEC-025":   "Load the encryption key from a KMS or the environment",
	"VULN-001":  "Remove eval and dispatch through an explicit map or parser",
	"VULN-002":  "Pass a fixed argument list to exec.Command instead of a shell string",
	"VULN-003":  "Drop shell=True and pass the command as an argument list",
	"VULN-004":  "Pass an argument array to child_process and validate each value",
	"VULN-005":  "Use a parameterized query instead of string formatting",
	"VULN-006":  "Parse untrusted data with JSON instead of pickle",
	"VULN-007":  "Use yaml.safe_load or yaml.SafeLoader",
	"AST-001":   "Check the returned error instead of discarding it",
	"AST-002":   "Close the channel or wait for the goroutine before returning",
	"TAINT-001": "Bind the value as a query parameter instead of concatenating it",
	"TAINT-002": "Pass fixed arguments to exec.Command, never a request value",
	"TAINT-003": "Clean the path and reject anything outside the base directory",
	"TAINT-004": "Allowlist the outbound host instead of using request input",
	"SC-001":    "Upgrade the dependency to the fixed version named in the advisory",
	"PLH-001":   "Implement the marked work or delete the placeholder",
	"PLH-002":   "Replace the placeholder marker with the real implementation",
	"PLH-003":   "Delete the stub comment or write the code it stands for",
	"PLH-004":   "Replace the placeholder package with a published dependency",
	"PLH-005":   "Log or return the error instead of swallowing it",
	"CFG-001":   "Disable debug mode outside local development",
	"CFG-002":   "Restrict CORS to the origins that actually call the API",
	"CFG-003":   "Restrict the file mode to 0600 or 0640",
	"CFG-004":   "Move the address into configuration or resolve it by name",
	"CFG-005":   "Serve the endpoint over https",
	"CFG-006":   "Disable tracebacks in production error responses",
	"CFG-007":   "Bind to the intended interface or 127.0.0.1",
	"FILE-001":  "Remove the env file from the repository and load secrets at runtime",
	"GO-003":    "Cancel the context or drain the goroutine before returning",
	"PY-001":    "Use subprocess with an argument list instead of exec",
	"PY-002":    "Replace eval with an explicit lookup or parser",
	"PY-003":    "Use tempfile.mkstemp or NamedTemporaryFile",
	"PY-004":    "Raise an explicit exception instead of relying on assert",
	"PAT-001":   "Assign textContent instead of building HTML",
	"PAT-002":   "Build the node with DOM APIs instead of document.write",
	"PAT-003":   "Bound the repetition or use a non-backtracking match",
	"PAT-004":   "Reject __proto__ and constructor keys or use a null-prototype object",
	"PAT-005":   "Parse untrusted input with JSON.parse",
	"PAT-006":   "Filter deserialized classes with an allowlist or use a safe format",
	"PAT-007":   "Disable external entities on the XML parser",
	"PAT-008":   "Resolve the path and reject anything outside the base directory",
	"PAT-009":   "Check the redirect target against an allowlist of hosts",
	"PAT-010":   "Allowlist the outbound host and block private address ranges",
	"QLT-001":   "Remove the debug print or route it through the logger",
	"QLT-002":   "Delete the commented-out code; version control keeps the history",
	"QLT-003":   "Name the constant and explain why the value was chosen",
	"QLT-004":   "Extract the inner block into a function or return early",
}

// FixFor returns the remediation text shown to a reviewer or an agent.
func FixFor(ruleID string) string {
	if fix, ok := fixes[ruleID]; ok {
		return fix
	}

	return FallbackFix
}

// FixText prefers the text carried by the finding, which is how custom rules
// supply their own remediation.
func (f Finding) FixText() string {
	if f.Fix != "" {
		return f.Fix
	}

	return FixFor(f.RuleID)
}
