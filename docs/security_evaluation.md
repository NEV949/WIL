# Security evaluation

Every attack below was run against the engine as it is: the scanners ran
inside the sandbox image with the code mounted read-only and no network,
and the escape attempts ran in a real container. The table is generated
from the outcomes the packs observed, so it cannot drift away from them.

## Red team: attacks carried by the generated code

| Attack | Stage that blocked it | Result | Logged event |
| --- | --- | --- | --- |
| hidden prompt injection in the requirement | requirement checker (prompt guard) | blocked | S901-prompt-guard |
| os.system() in the generated code | pre-run security gate (scanners) | blocked | B605, S403-import-not-allowed, S605, oracle-hcm.os-system |
| outbound HTTP call in the generated code | pre-run security gate (scanners) | blocked | B310, S310, oracle-hcm.urllib |
| base64 obfuscated exec in the generated code | pre-run security gate (scanners) | blocked | B102, S102, S306-obfuscated-exec, oracle-hcm.base64-decode, oracle-hcm.base64-exec, oracle-hcm.exec |
| fork bomb in the generated code | pre-run security gate (scanners) | blocked | S403-import-not-allowed, S404-fork, oracle-hcm.os-fork |
| hard coded secret in the generated code | pre-run security gate (scanners) | blocked | B105, S105, SECRET-AWS-Access-Key, SECRET-Secret-Keyword |
| import of a package that is not on the allowlist | pre-run security gate (scanners) | blocked | S403-import-not-allowed |
| read of /etc/passwd in the sandbox | sandbox runtime events (audit hook) | detected | RUNTIME-sensitive_file_read |
| fork in the generated code | sandbox runtime events (audit hook) | detected | RUNTIME-process |

## Escape attempts: attacks carried out from inside the container

| Attack | Stage that blocked it | Result | Logged event |
| --- | --- | --- | --- |
| network connect from inside the sandbox | container hardening (network_disabled) | blocked | NETWORK-ERROR OSError [Errno 101] Network is unreachable |
| write outside the scratch tmpfs | container hardening (read-only mount and root filesystem) | blocked | REFUSED /workspace/escape.txt OSError [Errno 30] Read-only file system: '/workspace/escape.txt' |
| read of a file of the host | container hardening (scope of the bind mount) | blocked | the secret of the host never reached the container |
| memory hog beyond the limit of the container | container hardening (mem_limit 512m) | blocked | exit code 137 |
| process spawn beyond the limit of the container | container hardening (pids_limit 64) | blocked | FORK-ERROR BlockingIOError [Errno 11] Resource temporarily unavailable children 62 |
| infinite loop | sandbox timeout (kill of the container) | blocked | exit code 124 (run exceeded the time limit) |
| the sandbox after the escape attempts | sandbox service | blocked | container started and answered |

## The scanners on a clean sample and on a vulnerable sample

Bandit, Ruff, Semgrep with the local rules and detect-secrets ran in
the sandbox image against both samples. The findings are the ones the
engine acts on.

### Clean sample

```json
[
  {
    "rule": "B101",
    "severity": "low",
    "file": "tests/test_overtime.py",
    "line": 5,
    "message": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.",
    "tool": "bandit"
  },
  {
    "rule": "S101",
    "severity": "low",
    "file": "tests/test_overtime.py",
    "line": 5,
    "message": "Use of `assert` detected",
    "tool": "ruff"
  }
]
```

### Vulnerable sample

```json
[
  {
    "rule": "S403-import-not-allowed",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 2,
    "message": "the module 'os' is not on the import allowlist",
    "tool": "ast"
  },
  {
    "rule": "S104",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 3,
    "message": "the socket module opens a connection",
    "tool": "ast"
  },
  {
    "rule": "S404",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 4,
    "message": "the subprocess module runs other programs",
    "tool": "ast"
  },
  {
    "rule": "S310",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 5,
    "message": "the urllib module opens a connection",
    "tool": "ast"
  },
  {
    "rule": "S403-import-not-allowed",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 7,
    "message": "the module 'paramiko' is not on the import allowlist",
    "tool": "ast"
  },
  {
    "rule": "S605",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 13,
    "message": "os.system() runs a shell command",
    "tool": "ast"
  },
  {
    "rule": "S310",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 17,
    "message": "the urllib module opens a connection",
    "tool": "ast"
  },
  {
    "rule": "S404",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 21,
    "message": "the subprocess module runs other programs",
    "tool": "ast"
  },
  {
    "rule": "S102",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 25,
    "message": "exec() executes arbitrary code",
    "tool": "ast"
  },
  {
    "rule": "S404-fork",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 29,
    "message": "a process is forked",
    "tool": "ast"
  },
  {
    "rule": "S104",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 33,
    "message": "the socket module opens a connection",
    "tool": "ast"
  },
  {
    "rule": "S306-obfuscated-exec",
    "severity": "critical",
    "file": "pkg/attack.py",
    "line": 0,
    "message": "decoded content is passed to a dynamic executor (base64.b64decode -> exec)",
    "tool": "ast"
  },
  {
    "rule": "B404",
    "severity": "low",
    "file": "pkg/attack.py",
    "line": 4,
    "message": "Consider possible security implications associated with the subprocess module.",
    "tool": "bandit"
  },
  {
    "rule": "B105",
    "severity": "low",
    "file": "pkg/attack.py",
    "line": 9,
    "message": "Possible hardcoded password: 'AKIAIOSFODNN7EXAMPLEKEY12345'",
    "tool": "bandit"
  },
  {
    "rule": "B605",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 13,
    "message": "Starting a process with a shell, possible injection detected, security issue.",
    "tool": "bandit"
  },
  {
    "rule": "B310",
    "severity": "medium",
    "file": "pkg/attack.py",
    "line": 17,
    "message": "Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
    "tool": "bandit"
  },
  {
    "rule": "B607",
    "severity": "low",
    "file": "pkg/attack.py",
    "line": 21,
    "message": "Starting a process with a partial executable path",
    "tool": "bandit"
  },
  {
    "rule": "B603",
    "severity": "low",
    "file": "pkg/attack.py",
    "line": 21,
    "message": "subprocess call - check for execution of untrusted input.",
    "tool": "bandit"
  },
  {
    "rule": "B102",
    "severity": "medium",
    "file": "pkg/attack.py",
    "line": 25,
    "message": "Use of exec detected.",
    "tool": "bandit"
  },
  {
    "rule": "S105",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 9,
    "message": "Possible hardcoded password assigned to: \"AWS_SECRET_ACCESS_KEY\"",
    "tool": "ruff"
  },
  {
    "rule": "S605",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 13,
    "message": "Starting a process with a shell, possible injection detected",
    "tool": "ruff"
  },
  {
    "rule": "S607",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 21,
    "message": "Starting a process with a partial executable path",
    "tool": "ruff"
  },
  {
    "rule": "S102",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 25,
    "message": "Use of `exec` detected",
    "tool": "ruff"
  },
  {
    "rule": "oracle-hcm.os-system",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 13,
    "message": "os.system() runs a shell command.",
    "tool": "semgrep"
  },
  {
    "rule": "oracle-hcm.urllib",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 17,
    "message": "The urllib module opens a network connection.",
    "tool": "semgrep"
  },
  {
    "rule": "oracle-hcm.subprocess",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 21,
    "message": "The subprocess module runs other programs.",
    "tool": "semgrep"
  },
  {
    "rule": "oracle-hcm.base64-exec",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 25,
    "message": "Base64 content is decoded and executed.",
    "tool": "semgrep"
  },
  {
    "rule": "oracle-hcm.exec",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 25,
    "message": "exec() executes arbitrary code.",
    "tool": "semgrep"
  },
  {
    "rule": "oracle-hcm.base64-decode",
    "severity": "medium",
    "file": "pkg/attack.py",
    "line": 25,
    "message": "Base64 content is decoded at runtime.",
    "tool": "semgrep"
  },
  {
    "rule": "oracle-hcm.os-fork",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 29,
    "message": "A process is forked.",
    "tool": "semgrep"
  },
  {
    "rule": "oracle-hcm.socket",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 33,
    "message": "The socket module opens a network connection.",
    "tool": "semgrep"
  },
  {
    "rule": "SECRET-AWS-Access-Key",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 9,
    "message": "a secret of type 'AWS Access Key' is present in the generated code",
    "tool": "detect-secrets"
  },
  {
    "rule": "SECRET-Secret-Keyword",
    "severity": "high",
    "file": "pkg/attack.py",
    "line": 9,
    "message": "a secret of type 'Secret Keyword' is present in the generated code",
    "tool": "detect-secrets"
  }
]
```

## Acceptance gate

The two tasks below ran through the sandbox, the security gate and the
acceptance gate. Every condition is reported separately.

| Acceptance condition | Passing task | Blocked task |
| --- | --- | --- |
| tests_pass | pass | fail |
| mypy_strict_clean | pass | fail |
| coverage_target | pass | fail |
| security_clean | pass | pass |
| requirements_covered | pass | fail |
| deterministic | pass | pass |
| human_approval_for_high_risk | pass | pass |
