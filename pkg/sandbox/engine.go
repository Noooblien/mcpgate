package sandbox

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Engine performs virtual tool sandboxing, command AST deconstruction, and path jail isolation.
type Engine struct {
	config SandboxConfig
}

// DefaultSandboxConfig provides production zero-trust defaults.
func DefaultSandboxConfig() SandboxConfig {
	return SandboxConfig{
		Mode:              ModeEnforcing,
		WorkspaceRoot:     "/workspace",
		BlockedSystemDirs: []string{"/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/var/run"},
		SensitiveFiles:    []string{"passwd", "shadow", "sudoers", "id_rsa", "id_ed25519", "authorized_keys", ".env", ".aws/credentials", ".bash_history"},
		MaxCommandPipes:   4,
		MaxArgLength:      4096,
		StrictPathJailing: true,
		AllowNetworkPipes: false,
	}
}

// NewEngine initializes the sandbox controller with configuration.
func NewEngine(cfg SandboxConfig) *Engine {
	if cfg.WorkspaceRoot == "" {
		cfg.WorkspaceRoot = "/workspace"
	}
	cfg.WorkspaceRoot = filepath.Clean(cfg.WorkspaceRoot)
	return &Engine{config: cfg}
}

// Regex patterns for dangerous execution signatures
var (
	reForkBomb         = regexp.MustCompile(`:\(\)\s*\{\s*:\|:&\s*\};:`)
	reReverseShellTCP  = regexp.MustCompile(`/dev/tcp/|/dev/udp/`)
	reReverseShellBin  = regexp.MustCompile(`\b(nc|ncat|netcat)\b.*(-e|--exec)\b`)
	reBashInteractive  = regexp.MustCompile(`bash\s+-i\s+>&`)
	rePrivEsc          = regexp.MustCompile(`\b(sudo|doas|pkexec|su\s+-)\b`)
	rePipeToShell      = regexp.MustCompile(`(curl|wget)\b.*\|\s*(sh|bash|zsh)\b`)
	reDestructiveDisk  = regexp.MustCompile(`\b(mkfs|fdisk|dd\s+if=)\b`)
	reDestructiveRM    = regexp.MustCompile(`rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+[/~*]`)
	reChmodRecursive   = regexp.MustCompile(`chmod\s+(-R\s+)?(777|0777)\s+[/~*]`)
)

// AuditPath inspects a file path against virtual workspace jailing and system directory protections.
func (e *Engine) AuditPath(rawPath string) (bool, string, []string, float64) {
	if rawPath == "" {
		return true, "", nil, 0.0
	}

	var violations []string
	var risk float64

	clean := filepath.Clean(rawPath)

	// 1. Path traversal dot checks
	if strings.Contains(rawPath, "..") {
		violations = append(violations, "Directory traversal sequence ('..') detected in path")
		risk += 35.0
	}

	// 2. Sensitive file patterns
	for _, sens := range e.config.SensitiveFiles {
		if strings.Contains(clean, sens) {
			violations = append(violations, fmt.Sprintf("Access to sensitive file pattern '%s' flagged", sens))
			risk += 45.0
			break
		}
	}

	// 3. Blocked system directories
	for _, sysDir := range e.config.BlockedSystemDirs {
		if clean == sysDir || strings.HasPrefix(clean, sysDir+"/") {
			violations = append(violations, fmt.Sprintf("Access to protected system directory '%s' forbidden", sysDir))
			risk += 50.0
			break
		}
	}

	// 4. Strict workspace jailing
	if e.config.StrictPathJailing {
		// If path is absolute, it must start with WorkspaceRoot
		if filepath.IsAbs(clean) {
			if !strings.HasPrefix(clean, e.config.WorkspaceRoot) {
				violations = append(violations, fmt.Sprintf("Path '%s' escapes virtual workspace jail '%s'", clean, e.config.WorkspaceRoot))
				risk += 40.0
			}
		} else {
			// Relative path evaluated against WorkspaceRoot
			joined := filepath.Clean(filepath.Join(e.config.WorkspaceRoot, clean))
			if !strings.HasPrefix(joined, e.config.WorkspaceRoot) {
				violations = append(violations, fmt.Sprintf("Relative path '%s' escapes virtual workspace jail '%s'", rawPath, e.config.WorkspaceRoot))
				risk += 40.0
			}
			clean = joined
		}
	}

	isAllowed := len(violations) == 0
	return isAllowed, clean, violations, risk
}

// AuditCommand deconstructs command lines into AST segments, identifying dangerous syscalls and pipes.
func (e *Engine) AuditCommand(cmd string) (bool, SandboxDecision, []string, []string, float64) {
	if strings.TrimSpace(cmd) == "" {
		return true, DecisionAllowed, nil, nil, 0.0
	}

	var violations []string
	var risk float64
	decision := DecisionAllowed

	// 1. Length guardrail
	if len(cmd) > e.config.MaxArgLength {
		violations = append(violations, fmt.Sprintf("Command length (%d bytes) exceeds max argument limit (%d bytes)", len(cmd), e.config.MaxArgLength))
		risk += 20.0
	}

	// 2. Fork bomb pattern
	if reForkBomb.MatchString(cmd) {
		violations = append(violations, "Deadly fork bomb pattern detected: ':(){ :|:& };:'")
		risk += 90.0
		decision = DecisionForkBombPattern
	}

	// 3. Destructive file / disk commands
	if reDestructiveRM.MatchString(cmd) {
		violations = append(violations, "Dangerous recursive root/home deletion detected ('rm -rf /')")
		risk += 95.0
		decision = DecisionDestructiveCommand
	}
	if reDestructiveDisk.MatchString(cmd) {
		violations = append(violations, "Low-level destructive disk block command detected ('mkfs' or 'dd')")
		risk += 90.0
		decision = DecisionDestructiveCommand
	}
	if reChmodRecursive.MatchString(cmd) {
		violations = append(violations, "Broad permissive permissions override detected ('chmod 777 /')")
		risk += 75.0
		decision = DecisionDestructiveCommand
	}

	// 4. Reverse shells & socket tunnels
	if !e.config.AllowNetworkPipes && (reReverseShellTCP.MatchString(cmd) || reReverseShellBin.MatchString(cmd) || reBashInteractive.MatchString(cmd)) {
		violations = append(violations, "Unauthorized interactive reverse shell socket pipe detected")
		risk += 95.0
		decision = DecisionReverseShell
	}

	// 5. Privilege escalation
	if rePrivEsc.MatchString(cmd) {
		violations = append(violations, "Unauthorized privilege escalation binary invocation ('sudo' / 'su' / 'doas')")
		risk += 80.0
		decision = DecisionPrivilegeEscalation
	}

	// 6. Pipe-to-shell injection
	if rePipeToShell.MatchString(cmd) {
		violations = append(violations, "Remote pipe-to-shell execution pattern detected ('curl | sh')")
		risk += 85.0
		decision = DecisionPipelineInjection
	}

	// 7. Pipeline segment deconstruction
	pipeCount := strings.Count(cmd, "|")
	if pipeCount > e.config.MaxCommandPipes {
		violations = append(violations, fmt.Sprintf("Pipeline complexity (%d pipes) exceeds maximum quota (%d)", pipeCount, e.config.MaxCommandPipes))
		risk += 30.0
		if decision == DecisionAllowed {
			decision = DecisionPipelineInjection
		}
	}

	// 8. Protected system paths or sensitive files within command string
	for _, sysDir := range e.config.BlockedSystemDirs {
		pattern := `(^|[\s"'>|&;])` + regexp.QuoteMeta(sysDir) + `(/|[\s"'<>&;|]|$)`
		if matched, _ := regexp.MatchString(pattern, cmd); matched {
			violations = append(violations, fmt.Sprintf("Command references protected system directory '%s'", sysDir))
			risk += 50.0
			if decision == DecisionAllowed {
				decision = DecisionProtectedPathAccess
			}
			break
		}
	}
	for _, sens := range e.config.SensitiveFiles {
		if strings.Contains(cmd, sens) {
			violations = append(violations, fmt.Sprintf("Command references sensitive file pattern '%s'", sens))
			risk += 45.0
			if decision == DecisionAllowed {
				decision = DecisionProtectedPathAccess
			}
			break
		}
	}

	// Parse command chunks
	segments := splitCommandPipeline(cmd)

	isAllowed := len(violations) == 0
	return isAllowed, decision, violations, segments, risk
}

// splitCommandPipeline separates compound shell commands into atomic segments.
func splitCommandPipeline(cmd string) []string {
	delimiters := regexp.MustCompile(`[;&|]+`)
	rawSegments := delimiters.Split(cmd, -1)
	var out []string
	for _, s := range rawSegments {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Evaluate evaluates a tool invocation against virtual path jailing and command AST safety boundaries.
func (e *Engine) Evaluate(req SandboxRequest) *SandboxEvaluation {
	start := time.Now()

	eval := &SandboxEvaluation{
		RequestID:   req.RequestID,
		AgentID:     req.AgentID,
		ToolName:    req.ToolName,
		Decision:    DecisionAllowed,
		EvaluatedAt: start,
	}

	var totalRisk float64
	var allViolations []string

	// Check path if supplied or in args
	targetPath := req.Path
	if targetPath == "" && req.Args != nil {
		for _, key := range []string{"path", "file", "target", "dir", "filepath"} {
			if val, ok := req.Args[key].(string); ok && val != "" {
				targetPath = val
				break
			}
		}
	}

	if targetPath != "" {
		pathOk, cleanPath, pathViolations, pathRisk := e.AuditPath(targetPath)
		eval.SanitizedPath = cleanPath
		totalRisk += pathRisk
		allViolations = append(allViolations, pathViolations...)
		if !pathOk {
			if strings.Contains(strings.Join(pathViolations, " "), "escapes virtual workspace") {
				eval.Decision = DecisionPathJailEscape
			} else {
				eval.Decision = DecisionProtectedPathAccess
			}
		}
	}

	// Check command if supplied or in args
	targetCmd := req.Command
	if targetCmd == "" && req.Args != nil {
		for _, key := range []string{"cmd", "command", "script", "exec", "query"} {
			if val, ok := req.Args[key].(string); ok && val != "" {
				targetCmd = val
				break
			}
		}
	}

	if targetCmd != "" {
		cmdOk, cmdDecision, cmdViolations, segments, cmdRisk := e.AuditCommand(targetCmd)
		eval.ParsedCommands = segments
		totalRisk += cmdRisk
		allViolations = append(allViolations, cmdViolations...)
		if !cmdOk && eval.Decision == DecisionAllowed {
			eval.Decision = cmdDecision
		}
	}

	eval.Violations = allViolations
	eval.RiskScore = math.Min(100.0, math.Round(totalRisk*10)/10)

	// Determine Isolation Tier
	switch {
	case eval.RiskScore <= 15.0:
		eval.IsolationTier = TierPristine
	case eval.RiskScore <= 45.0:
		eval.IsolationTier = TierGuarded
	case eval.RiskScore <= 75.0:
		eval.IsolationTier = TierSuspicious
	default:
		eval.IsolationTier = TierHostile
	}

	// Determine allowance
	if e.config.Mode == ModeDisabled {
		eval.IsAllowed = true
		eval.ContainmentNote = "Sandbox disabled: execution permitted without policy boundary enforcement"
	} else if e.config.Mode == ModeAudit {
		eval.IsAllowed = true
		if len(allViolations) > 0 {
			eval.ContainmentNote = fmt.Sprintf("AUDIT WARNING: %d violations flagged (Risk: %.1f/100, Tier: %s)",
				len(allViolations), eval.RiskScore, eval.IsolationTier)
		} else {
			eval.ContainmentNote = "Clean execution verified inside virtual workspace"
		}
	} else { // ModeEnforcing
		if eval.RiskScore >= 70.0 || len(allViolations) > 0 {
			eval.IsAllowed = false
			eval.ContainmentNote = fmt.Sprintf("ENFORCEMENT BLOCK: Quarantined %s execution. %d security violations (Risk: %.1f/100, Tier: %s)",
				eval.Decision, len(allViolations), eval.RiskScore, eval.IsolationTier)
		} else {
			eval.IsAllowed = true
			eval.ContainmentNote = "Execution authorized: Bounded within virtual workspace and safe AST profile"
		}
	}

	eval.Duration = time.Since(start)
	return eval
}
