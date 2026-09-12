#!/usr/bin/env nu
# readiness.nu — canonical validator for the readiness/v1 change-control contract.
#
# Canonical source: Eugene3dotdev/dotfiles, readiness/readiness.nu. Every other
# repository carries a byte-identical vendored copy under .readiness/ plus a
# lock.yaml that pins this file's sha256; `readiness.nu audit` (run from
# dotfiles) reports any copy that drifts from the canonical file.
#
# The contract this file implements is described for humans in
# readiness/contract/readiness-contract.v1.yaml. The machine-readable parts
# (states, blast-radius classes, evidence kinds, staleness limits, execution
# path patterns) are the constants below; readiness/tests asserts that the two
# agree, so a contract change is one commit touching both.
#
# Untrusted-data boundary: Linear issue descriptions and comments are external
# text. This validator reads exactly one fenced ```readiness block and the
# fenced ```readiness-evidence blocks, parses them as YAML with a closed key
# set, and never interprets any other text. Nothing in an issue can change what
# this validator does; it can only make the verdict "not ready".

const SELF = (path self)
const CONTRACT = "readiness/v1"
const SUPPORTED_RECORD_CONTRACTS = ["readiness/v1"]
const ADAPTER_SCHEMA = "readiness-adapter/v1"
const LOCK_SCHEMA = "readiness-lock/v1"
const REGISTRY_SCHEMA = "readiness-registry/v1"
const LINEAR_URL = "https://api.linear.app/graphql"
const GITHUB_API = "https://api.github.com"
const MAX_VALIDITY_DAYS = 30
const DEFAULT_VALIDITY_DAYS = 14
const DEFAULT_ISSUE_PREFIX = "TEO"

const STATES = ["draft" "ready" "blocked" "done" "superseded"]

# Blast-radius classes, ordered. A record's declared class must rank at or
# above the class the changed paths require. Evidence kinds are what a change
# of that class must record back to its Linear issue before it is applied.
const CLASSES = [
  [name rank evidence];
  ["local" 1 ["source-validation"]]
  ["workstation" 2 ["source-validation" "dry-run-apply"]]
  ["release" 3 ["source-validation" "release-verification"]]
  ["service" 4 ["source-validation" "dry-run-apply" "rollback-plan"]]
  ["edge" 5 ["source-validation" "dry-run-apply" "signed-receipt" "backup-verified" "restore-drill" "rollback-plan"]]
  ["cluster" 6 ["source-validation" "rendered-manifests" "reconcile-dry-run" "live-cluster-validation" "secret-handling" "rollback-plan" "reapply-idempotency"]]
]

const EVIDENCE_KINDS = [
  "source-validation" "dry-run-apply" "release-verification" "rollback-plan"
  "signed-receipt" "backup-verified" "restore-drill" "rendered-manifests"
  "reconcile-dry-run" "live-cluster-validation" "secret-handling"
  "reapply-idempotency" "live-git-probe"
]
const EVIDENCE_STATUSES = ["pass" "fail" "degraded"]

const RECORD_KEYS = ["contract" "issue" "state" "blast_radius" "repos" "scope_digest" "approved_by" "approved_at" "expires_at" "exceptions" "notes"]
const RECORD_REQUIRED = ["contract" "issue" "state" "blast_radius" "repos"]
const READY_REQUIRED = ["scope_digest" "approved_by" "approved_at" "expires_at"]
const EXCEPTION_KEYS = ["id" "waives" "owner" "expires_at" "approval" "follow_up" "reason"]
const EXCEPTION_REQUIRED = ["id" "waives" "owner" "expires_at" "approval" "follow_up"]
const EVIDENCE_KEYS = ["contract" "repo" "kind" "status" "ref" "control_point" "run" "recorded_at" "fingerprint" "note"]
const EVIDENCE_REQUIRED = ["contract" "repo" "kind" "status" "ref" "control_point" "recorded_at" "fingerprint"]

# Execution paths a repository can have. Discovery lists every tracked file
# matching one of these and compares it with the adapter's control points; a
# match the adapter neither registers nor ignores is an enforcement gap.
const EXECUTION_PATHS = [
  [kind glob];
  ["github-workflow" ".github/workflows/*.yml"]
  ["github-workflow" ".github/workflows/*.yaml"]
  ["forgejo-workflow" ".forgejo/workflows/*.yml"]
  ["forgejo-workflow" ".forgejo/workflows/*.yaml"]
  ["gitea-workflow" ".gitea/workflows/*.yml"]
  ["gitea-workflow" ".gitea/workflows/*.yaml"]
  ["gitlab-ci" ".gitlab-ci.yml"]
  ["pre-commit" ".pre-commit-config.yaml"]
  ["agent-hooks" ".claude/settings.json"]
  ["agent-hook" ".claude/hooks/*"]
  ["agent-release-skill" ".claude/skills/release/SKILL.md"]
  ["verify-script" "scripts/verify-*"]
  ["release-script" "scripts/release*"]
  ["deploy-script" "**/deploy*.sh"]
  ["deploy-script" "**/deploy*.nu"]
  ["reconciler" "apply/Cargo.toml"]
  ["reconciler" "edge/*/reconcile.nu"]
  ["gitops-app" "**/argocd/applications.yaml"]
  ["homebrew-formula" "Formula/*.rb"]
  ["task-runner" "Makefile"]
  ["task-runner" "justfile"]
  ["task-runner" "Taskfile.yml"]
  ["build-script" "**/build.sh"]
]

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def now-utc [] { date now | date to-timezone UTC }

def fmt-ts [d] { $d | date to-timezone UTC | format date "%Y-%m-%dT%H:%M:%SZ" }

def parse-ts [s] {
  if (($s | describe) != "string") { return null }
  if not ($s =~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$') { return null }
  try { $s | into datetime | date to-timezone UTC } catch { null }
}

def is-string [v] { ($v | describe) == "string" }
def is-list [v] { let d = ($v | describe); ($d starts-with "list") or ($d starts-with "table") }
def is-record [v] { ($v | describe) starts-with "record" }

def short-hash [s: string] { $s | hash sha256 | str substring 0..<16 }

def class-row [name] { $CLASSES | where name == $name | get -o 0 }
def class-rank [name] { let r = (class-row $name); if ($r == null) { 0 } else { $r.rank } }
def class-names [] { $CLASSES | get name }
def max-class [names: list<string>] {
  $names | reduce -f "local" {|it, acc| if (class-rank $it) > (class-rank $acc) { $it } else { $acc } }
}

# glob → anchored regex. `**` spans directories, `*` a single segment, `?` one char.
def glob-regex [g: string] {
  let escaped = ($g
    | str replace --all -r '([.+^$(){}|\[\]\\])' '\$1'
    | str replace --all '**/' "\u{1}"
    | str replace --all '**' "\u{2}"
    | str replace --all '*' '[^/]*'
    | str replace --all '?' '[^/]'
    | str replace --all "\u{1}" '(?:.*/)?'
    | str replace --all "\u{2}" '.*')
  $"^($escaped)$"
}
def glob-match [g: string, path: string] { $path =~ (glob-regex $g) }

def git-root [dir] {
  let r = (^git -C $dir rev-parse --show-toplevel | complete)
  if $r.exit_code != 0 { error make {msg: $"not a git repository: ($dir)"} }
  $r.stdout | str trim
}

def tracked-files [dir] {
  let r = (^git -C $dir ls-files | complete)
  if $r.exit_code != 0 { error make {msg: $"git ls-files failed in ($dir): ($r.stderr | str trim)"} }
  $r.stdout | lines | where {|l| ($l | str trim | is-not-empty) }
}

def changed-files [dir, base: string, head: string] {
  let r = (^git -C $dir diff --name-only $"($base)...($head)" | complete)
  if $r.exit_code != 0 {
    let r2 = (^git -C $dir diff --name-only $base $head | complete)
    if $r2.exit_code != 0 { error make {msg: $"git diff ($base)...($head) failed: ($r.stderr | str trim)"} }
    return ($r2.stdout | lines | where {|l| ($l | str trim | is-not-empty) })
  }
  $r.stdout | lines | where {|l| ($l | str trim | is-not-empty) }
}

def finding [code: string, message: string] { {code: $code, message: $message} }

# ---------------------------------------------------------------------------
# adapter / lock / registry
# ---------------------------------------------------------------------------

def adapter-path [root] {
  let candidates = [
    ([$root ".readiness" "adapter.yaml"] | path join)
    ([$root "readiness" "adapter.yaml"] | path join)
  ]
  let hit = ($candidates | where {|p| $p | path exists })
  if ($hit | is-empty) { null } else { $hit | first }
}

def load-adapter [root] {
  let p = (adapter-path $root)
  if ($p == null) {
    error make {msg: $"no readiness adapter in ($root): expected .readiness/adapter.yaml \(or readiness/adapter.yaml in the canonical repository\)"}
  }
  let a = (open --raw $p | from yaml)
  if (($a | get -o adapter) != $ADAPTER_SCHEMA) { error make {msg: $"($p): adapter schema must be ($ADAPTER_SCHEMA)"} }
  if (($a | get -o contract_version) not-in $SUPPORTED_RECORD_CONTRACTS) { error make {msg: $"($p): contract_version ($a | get -o contract_version) is not supported by this validator \(($CONTRACT)\)"} }
  for key in ["repo" "path_classes" "control_points"] {
    if (($a | get -o $key) == null) { error make {msg: $"($p): missing required key ($key)"} }
  }
  for pc in $a.path_classes {
    if (($pc | get -o glob) == null or ($pc | get -o class) == null) { error make {msg: $"($p): every path_classes entry needs glob and class"} }
    if ($pc.class not-in (class-names)) { error make {msg: $"($p): unknown class ($pc.class) in path_classes"} }
    for e in ($pc | get -o extra_evidence | default []) {
      if ($e not-in $EVIDENCE_KINDS) { error make {msg: $"($p): unknown extra_evidence kind ($e)"} }
    }
  }
  for cp in $a.control_points {
    for key in ["id" "kind" "path" "enforces"] {
      if (($cp | get -o $key) == null) { error make {msg: $"($p): control point missing ($key)"} }
    }
  }
  $a | insert _path $p | insert _dir ($p | path dirname)
}

def lock-path [dir] { [$dir "lock.yaml"] | path join }

def validator-sha [file] { open --raw $file | hash sha256 }

# ---------------------------------------------------------------------------
# record extraction and validation
# ---------------------------------------------------------------------------

# Fenced blocks whose info string is exactly `lang`. Returns list of bodies.
def fenced-blocks [text: string, lang: string] {
  let ls = ($text | lines)
  let marks = ($ls | enumerate | where {|e| ($e.item | str trim) == $"```($lang)" } | get index)
  $marks | each {|start|
    let rest = ($ls | skip ($start + 1))
    let end = ($rest | enumerate | where {|e| ($e.item | str trim) starts-with "```" } | get -o 0.index)
    if ($end == null) { null } else { $rest | first $end | str join "\n" }
  } | compact
}

def strip-blocks [text: string, lang: string] {
  let ls = ($text | lines)
  # drop lines from each opening fence to its closing fence inclusive
  let out = ($ls | reduce -f {keep: [], inside: false} {|line, acc|
    let t = ($line | str trim)
    if $acc.inside {
      if ($t starts-with "```") { {keep: $acc.keep, inside: false} } else { $acc }
    } else if ($t == $"```($lang)") {
      {keep: $acc.keep, inside: true}
    } else {
      {keep: ($acc.keep | append $line), inside: false}
    }
  })
  $out.keep | str join "\n"
}

# Linear re-renders markdown on save (bullets become `*`), so list markers are
# canonicalized before hashing; otherwise a record stamped offline would read
# as stale once the description round-trips through Linear.
def normalize-text [text: string] {
  $text
    | lines
    | each {|l| $l | str trim --right }
    | each {|l| $l | str replace -r '^(\s*)[*+]\s+' '$1- ' }
    | str join "\n"
    | str replace --all -r '\n{3,}' "\n\n"
    | str trim
}

# The scope section is the `## Scope` heading (any case) up to the next `## `
# heading. Without one, the whole description minus the readiness block.
def scope-text [description: string] {
  let body = (strip-blocks $description "readiness")
  let ls = ($body | lines)
  let start = ($ls | enumerate | where {|e| ($e.item | str trim) =~ '(?i)^##\s+scope\s*$' } | get -o 0.index)
  if ($start == null) { return (normalize-text $body) }
  let rest = ($ls | skip ($start + 1))
  let end = ($rest | enumerate | where {|e| ($e.item | str trim) =~ '^##\s+' } | get -o 0.index)
  let section = if ($end == null) { $rest } else { $rest | first $end }
  normalize-text ($section | str join "\n")
}

export def scope-digest [description: string] { short-hash (scope-text $description) }

def parse-yaml-block [body: string] {
  let parsed = (try { $body | from yaml } catch { null })
  if not (is-record $parsed) { null } else { $parsed }
}

# Structural validation of a record. Returns list of findings (empty = valid).
def validate-record-shape [rec] {
  mut f = []
  let keys = ($rec | columns)
  for k in $keys { if ($k not-in $RECORD_KEYS) { $f = ($f | append (finding "invalid" $"unknown key `($k)` in readiness block")) } }
  for k in $RECORD_REQUIRED { if (($rec | get -o $k) == null) { $f = ($f | append (finding "invalid" $"missing required key `($k)`")) } }
  if ($f | is-not-empty) { return $f }
  if not (is-string $rec.contract) or ($rec.contract not-in $SUPPORTED_RECORD_CONTRACTS) {
    $f = ($f | append (finding "invalid" $"contract `($rec.contract)` is not supported by this validator \(supports ($SUPPORTED_RECORD_CONTRACTS | str join ', ')\)"))
  }
  if not (is-string $rec.issue) or not ($rec.issue =~ '^[A-Z][A-Z0-9]+-[0-9]+$') { $f = ($f | append (finding "invalid" "issue must be an identifier like TEO-1234")) }
  if not (is-string $rec.state) or ($rec.state not-in $STATES) { $f = ($f | append (finding "invalid" $"state must be one of ($STATES | str join ', ')")) }
  if not (is-string $rec.blast_radius) or ($rec.blast_radius not-in (class-names)) { $f = ($f | append (finding "invalid" $"blast_radius must be one of ((class-names) | str join ', ')")) }
  if not (is-list $rec.repos) or ($rec.repos | is-empty) or not ($rec.repos | all {|r| (is-string $r) and ($r =~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') }) {
    $f = ($f | append (finding "invalid" "repos must be a non-empty list of owner/name entries"))
  }
  if (($rec | get -o scope_digest) != null) and (not (is-string $rec.scope_digest) or not ($rec.scope_digest =~ '^[0-9a-f]{16}$')) {
    $f = ($f | append (finding "invalid" "scope_digest must be 16 lowercase hex characters"))
  }
  for k in ["approved_at" "expires_at"] {
    let v = ($rec | get -o $k)
    if ($v != null) and ((parse-ts $v) == null) { $f = ($f | append (finding "invalid" $"($k) must be an RFC 3339 timestamp")) }
  }
  if (($rec | get -o approved_by) != null) and (not (is-string $rec.approved_by) or ($rec.approved_by | str trim | is-empty)) {
    $f = ($f | append (finding "invalid" "approved_by must be a non-empty string"))
  }
  let exceptions = ($rec | get -o exceptions | default [])
  if not (is-list $exceptions) { $f = ($f | append (finding "invalid" "exceptions must be a list")) } else {
    for e in $exceptions {
      if not (is-record $e) { $f = ($f | append (finding "invalid" "each exception must be a mapping")); continue }
      for k in ($e | columns) { if ($k not-in $EXCEPTION_KEYS) { $f = ($f | append (finding "invalid" $"unknown exception key `($k)`")) } }
      for k in $EXCEPTION_REQUIRED { if (($e | get -o $k) == null) { $f = ($f | append (finding "invalid" $"exception missing `($k)`")) } }
      let w = ($e | get -o waives | default [])
      if not (is-list $w) or ($w | is-empty) or not ($w | all {|x| $x in $EVIDENCE_KINDS }) { $f = ($f | append (finding "invalid" "exception.waives must list known evidence kinds")) }
      if ((parse-ts ($e | get -o expires_at)) == null) { $f = ($f | append (finding "invalid" "exception.expires_at must be an RFC 3339 timestamp")) }
      let fu = ($e | get -o follow_up)
      if ($fu != null) and (not (is-string $fu) or not ($fu =~ '^[A-Z][A-Z0-9]+-[0-9]+$')) { $f = ($f | append (finding "invalid" "exception.follow_up must be a Linear issue identifier")) }
      let ap = ($e | get -o approval)
      if ($ap != null) and (not (is-string $ap) or ($ap | str trim | is-empty)) { $f = ($f | append (finding "invalid" "exception.approval must be a non-empty reference")) }
    }
  }
  $f
}

# Semantic validation against context. ctx: {now, description, repo, required_class, issue_state_type}
def validate-record-semantics [rec, ctx] {
  mut f = []
  let now = $ctx.now
  if $rec.state != "ready" {
    $f = ($f | append (finding "not-ready" $"record state is `($rec.state)`"))
  } else {
    for k in $READY_REQUIRED { if (($rec | get -o $k) == null) { $f = ($f | append (finding "invalid" $"state ready requires `($k)`")) } }
  }
  if ($f | where code == "invalid" | is-not-empty) { return $f }
  let ist = ($ctx | get -o issue_state_type)
  if ($ist != null) and ($ist in ["completed" "canceled" "cancelled"]) {
    $f = ($f | append (finding "not-ready" $"Linear issue state is ($ist)"))
  }
  if $rec.state == "ready" {
    let approved = (parse-ts $rec.approved_at)
    let expires = (parse-ts $rec.expires_at)
    if $expires <= $approved { $f = ($f | append (finding "invalid" "expires_at must be after approved_at")) }
    if ($expires - $approved) > ($MAX_VALIDITY_DAYS * 1day) { $f = ($f | append (finding "invalid" $"readiness may not be valid for more than ($MAX_VALIDITY_DAYS) days")) }
    if $approved > ($now + 5min) { $f = ($f | append (finding "invalid" "approved_at is in the future")) }
    if $expires <= $now { $f = ($f | append (finding "stale" $"readiness expired at ($rec.expires_at)")) }
    let digest = (scope-digest $ctx.description)
    if $digest != $rec.scope_digest {
      $f = ($f | append (finding "stale" $"scope changed since approval: record digest ($rec.scope_digest), current ($digest); re-run `readiness.nu stamp`"))
    }
  }
  let repo = ($ctx | get -o repo)
  if ($repo != null) and ($repo not-in $rec.repos) {
    $f = ($f | append (finding "out-of-scope" $"repository ($repo) is not listed in the record's repos"))
  }
  let required = ($ctx | get -o required_class)
  if ($required != null) and ((class-rank $rec.blast_radius) < (class-rank $required)) {
    $f = ($f | append (finding "insufficient" $"changed paths require blast_radius `($required)`; record declares `($rec.blast_radius)`"))
  }
  for e in ($rec | get -o exceptions | default []) {
    let ex = (parse-ts $e.expires_at)
    if $ex <= $now { $f = ($f | append (finding "invalid" $"exception ($e.id) expired at ($e.expires_at)")) }
    if (($ex - $now) > ($MAX_VALIDITY_DAYS * 1day)) { $f = ($f | append (finding "invalid" $"exception ($e.id) may not run more than ($MAX_VALIDITY_DAYS) days ahead")) }
  }
  $f
}

def active-waivers [rec, now] {
  $rec | get -o exceptions | default [] | where {|e| (parse-ts $e.expires_at) > $now } | get waives | flatten | uniq
}

# Evidence blocks from comments: list of {body, createdAt} → parsed evidence records.
def parse-evidence [comments] {
  $comments | each {|c|
    fenced-blocks ($c | get -o body | default "") "readiness-evidence" | each {|b|
      let r = (parse-yaml-block $b)
      if ($r == null) { null } else {
        let bad_keys = ($r | columns | where {|k| $k not-in $EVIDENCE_KEYS })
        let missing = ($EVIDENCE_REQUIRED | where {|k| ($r | get -o $k) == null })
        if ($bad_keys | is-not-empty) or ($missing | is-not-empty) { null } else { $r }
      }
    }
  } | flatten | compact
}

def evidence-fingerprint [repo: string, kind: string, ref: string, status: string] {
  short-hash $"($repo)|($kind)|($ref)|($status)"
}

def check-evidence [evidence, repo: string, required: list<string>, ref, any_ref: bool] {
  $required | each {|kind|
    let hits = ($evidence | where {|e|
      let ident = (($e.repo == $repo) and ($e.kind == $kind) and ($e.status == "pass") and ($e.contract in $SUPPORTED_RECORD_CONTRACTS))
      let genuine = ($e.fingerprint == (evidence-fingerprint $e.repo $e.kind $e.ref $e.status))
      let ref_ok = ($any_ref or (($ref != null) and ($e.ref == $ref)))
      $ident and $genuine and $ref_ok
    })
    if ($hits | is-empty) {
      let scope = if $any_ref { "any ref" } else { $"ref ($ref | default 'unknown')" }
      finding "evidence-missing" $"no passing `($kind)` evidence recorded for ($repo) at ($scope)"
    } else { null }
  } | compact
}

# ---------------------------------------------------------------------------
# Linear
# ---------------------------------------------------------------------------

def linear-key [] {
  let k = ($env | get -o LINEAR_API_KEY | default "")
  if ($k | str trim | is-empty) {
    error make {msg: "LINEAR_API_KEY is not set; the readiness gate fails closed without Linear access (use --record <file> for an offline check)"}
  }
  $k
}

def linear-graphql [query: string, variables] {
  let resp = (http post --full --allow-errors --content-type application/json --headers ["Authorization" (linear-key)] $LINEAR_URL ({query: $query, variables: $variables} | to json))
  if $resp.status != 200 { error make {msg: $"Linear API returned HTTP ($resp.status): ($resp.body | to json --raw | str substring 0..<300)"} }
  let body = $resp.body
  let errs = ($body | get -o errors | default [])
  if ($errs | is-not-empty) { error make {msg: $"Linear API error: ($errs | get message | str join '; ')"} }
  $body.data
}

def linear-issue [identifier: string] {
  let q = "query($id: String!) { issue(id: $id) { id identifier title url description updatedAt state { name type } comments(first: 250) { nodes { id body createdAt } } } }"
  let d = (linear-graphql $q {id: $identifier})
  if (($d | get -o issue) == null) { error make {msg: $"Linear issue ($identifier) not found"} }
  $d.issue
}

def linear-comment-create [issue_id: string, body: string] {
  let m = "mutation($input: CommentCreateInput!) { commentCreate(input: $input) { success comment { id url } } }"
  linear-graphql $m {input: {issueId: $issue_id, body: $body}}
}

def linear-issue-update-description [issue_id: string, description: string] {
  let m = "mutation($id: String!, $input: IssueUpdateInput!) { issueUpdate(id: $id, input: $input) { success } }"
  linear-graphql $m {id: $issue_id, input: {description: $description}}
}

# ---------------------------------------------------------------------------
# issue reference resolution
# ---------------------------------------------------------------------------

def issue-ref-in [text, prefix: string] {
  if (not (is-string $text)) or ($text | is-empty) { return null }
  let re = ('\b(' + $prefix + '-[0-9]+)\b')
  let hits = ($text | parse -r $re | get -o capture0)
  if ($hits == null) or ($hits | is-empty) { null } else { $hits | first }
}

def github-event [] {
  let p = ($env | get -o GITHUB_EVENT_PATH | default "")
  if ($p | is-empty) or not ($p | path exists) { return null }
  try { open --raw $p | from json } catch { null }
}

# ---------------------------------------------------------------------------
# verdict rendering
# ---------------------------------------------------------------------------

def verdict-status [findings] {
  if ($findings | is-empty) { return "ready" }
  let order = ["unavailable" "missing" "invalid" "not-ready" "stale" "out-of-scope" "insufficient" "evidence-missing"]
  $order | where {|s| $findings | any {|f| $f.code == $s } } | first
}

def print-verdict [v, json: bool] {
  if $json { print ($v | to json); return }
  let mark = if $v.ok { "READY" } else { "NOT READY" }
  print $"readiness ($CONTRACT): ($mark) [($v.status)] issue=($v.issue | default '-') repo=($v.repo | default '-') required_class=($v.required_class | default '-') declared_class=($v.declared_class | default '-')"
  for f in $v.findings { print $"  - ($f.code): ($f.message)" }
  if ($v | get -o evidence_required | default [] | is-not-empty) { print $"  evidence required: ($v.evidence_required | str join ', ')" }
}

def make-verdict [status: string, findings, extra] {
  {
    contract: $CONTRACT
    status: $status
    ok: ($status == "ready")
    checked_at: (fmt-ts (now-utc))
    findings: $findings
  } | merge $extra
}

def exit-with [v, json: bool] {
  print-verdict $v $json
  if $v.ok { exit 0 } else { exit 1 }
}

# ---------------------------------------------------------------------------
# main commands
# ---------------------------------------------------------------------------

def main [] {
  print $"readiness.nu ($CONTRACT) — canonical readiness validator"
  print "subcommands: check, parse, digest, stamp, template, evidence, comment, discover, audit, lock, version"
  print "run `nu readiness.nu <subcommand> --help` for flags"
}

def "main version" [] { print $CONTRACT }

# Validate the readiness record for a change in this repository.
def "main check" [
  --issue: string          # Linear identifier (TEO-1234); resolved from --title/--branch/--body/GITHUB_EVENT_PATH/HEAD message when omitted
  --record: path           # offline: file holding the Linear issue description (with its ```readiness block)
  --comments: path         # offline: JSON list of {body, createdAt} comments used for --require-evidence
  --issue-state: string    # offline: Linear workflow state type (started, completed, canceled ...)
  --repo-dir: path         # repository root (default: current directory's git root)
  --repo: string           # owner/name override (default: adapter.repo)
  --base: string           # base ref for changed-path classification
  --head: string = "HEAD"  # head ref for changed-path classification
  --files: string          # explicit changed paths, comma-separated (overrides --base/--head)
  --title: string          # PR title (issue reference source)
  --branch: string         # branch name (issue reference source)
  --body: string           # PR body (issue reference source)
  --require-evidence       # also require passing evidence comments for every evidence kind of the required class
  --ref: string            # evidence must be recorded for this git ref (default: resolved head sha)
  --any-ref                # accept evidence recorded for any ref
  --actor: string          # actor login; adapter.exempt_actors may skip the gate (audited)
  --now: string            # override current time (tests)
  --json                   # machine-readable verdict on stdout
] {
  let now = if ($now == null) { now-utc } else { let t = (parse-ts $now); if ($t == null) { error make {msg: "--now must be RFC 3339"} }; $t }
  let root = (git-root ($repo_dir | default (pwd)))
  let adapter = (load-adapter $root)
  let repo_name = ($repo | default $adapter.repo)
  let prefix = ($adapter | get -o issue_prefix | default $DEFAULT_ISSUE_PREFIX)

  if ($actor != null) and ($actor in ($adapter | get -o exempt_actors | default [])) {
    let v = (make-verdict "ready" [] {issue: null, repo: $repo_name, required_class: null, declared_class: null, exempt_actor: $actor, evidence_required: []})
    exit-with $v $json
  }

  # 1. issue reference
  let event = (github-event)
  let pr = if ($event == null) { null } else { $event | get -o pull_request }
  let head_msg = (^git -C $root log -1 --format=%B $head | complete | get stdout)
  let sources = [
    $issue
    (issue-ref-in $title $prefix)
    (issue-ref-in $branch $prefix)
    (issue-ref-in $body $prefix)
    (if ($pr == null) { null } else { issue-ref-in ($pr | get -o title) $prefix })
    (if ($pr == null) { null } else { issue-ref-in ($pr | get -o head.ref) $prefix })
    (if ($pr == null) { null } else { issue-ref-in ($pr | get -o body) $prefix })
    (issue-ref-in $head_msg $prefix)
  ] | compact
  if ($sources | is-empty) {
    let v = (make-verdict "missing" [(finding "missing" $"no ($prefix)-<n> issue reference in the PR title, branch, body, or head commit message")] {issue: null, repo: $repo_name, required_class: null, declared_class: null, evidence_required: []})
    exit-with $v $json
  }
  let issue_id = ($sources | first)

  # 2. changed paths → required class and evidence
  let paths = if ($files != null) { $files | split row "," | each {|p| $p | str trim } | where {|p| $p | is-not-empty } } else if ($base != null) { changed-files $root $base $head } else if ($pr != null) {
    let base_sha = ($pr | get -o base.sha)
    let head_sha = ($pr | get -o head.sha)
    if ($base_sha == null or $head_sha == null) { [] } else { try { changed-files $root $base_sha $head_sha } catch { [] } }
  } else { [] }
  let matched = if ($paths | is-empty) {
    # nothing known about the change: fail closed to the strictest class the adapter declares
    $adapter.path_classes
  } else {
    $paths | each {|p| $adapter.path_classes | where {|pc| glob-match $pc.glob $p } | get -o 0 } | compact
  }
  let required_class = (max-class ($matched | get class))
  let evidence_required = (
    ((class-row $required_class).evidence)
    | append ($matched | each {|m| $m | get -o extra_evidence | default [] } | flatten)
    | uniq
  )

  # 3. issue content
  let loaded = if ($record != null) {
    {description: (open --raw $record), state_type: $issue_state, id: null, comments: (if ($comments == null) { [] } else { open --raw $comments | from json })}
  } else {
    let r = (try { {ok: true, issue: (linear-issue $issue_id)} } catch {|e| {ok: false, msg: $e.msg} })
    if not $r.ok {
      let v = (make-verdict "unavailable" [(finding "unavailable" $r.msg)] {issue: $issue_id, repo: $repo_name, required_class: $required_class, declared_class: null, evidence_required: $evidence_required})
      exit-with $v $json
    }
    {description: ($r.issue | get -o description | default ""), state_type: ($r.issue | get -o state.type), id: $r.issue.id, comments: ($r.issue | get -o comments.nodes | default [])}
  }

  # 4. record
  let blocks = (fenced-blocks $loaded.description "readiness")
  if ($blocks | is-empty) {
    let v = (make-verdict "missing" [(finding "missing" $"issue ($issue_id) has no ```readiness block; create it from `readiness.nu template`")] {issue: $issue_id, repo: $repo_name, required_class: $required_class, declared_class: null, evidence_required: $evidence_required})
    exit-with $v $json
  }
  if ($blocks | length) > 1 {
    let v = (make-verdict "invalid" [(finding "invalid" "issue has more than one readiness block")] {issue: $issue_id, repo: $repo_name, required_class: $required_class, declared_class: null, evidence_required: $evidence_required})
    exit-with $v $json
  }
  let rec = (parse-yaml-block ($blocks | first))
  if ($rec == null) {
    let v = (make-verdict "invalid" [(finding "invalid" "readiness block is not a YAML mapping")] {issue: $issue_id, repo: $repo_name, required_class: $required_class, declared_class: null, evidence_required: $evidence_required})
    exit-with $v $json
  }
  let shape = (validate-record-shape $rec)
  if ($shape | is-not-empty) {
    let v = (make-verdict "invalid" $shape {issue: $issue_id, repo: $repo_name, required_class: $required_class, declared_class: ($rec | get -o blast_radius), evidence_required: $evidence_required})
    exit-with $v $json
  }
  if $rec.issue != $issue_id {
    let v = (make-verdict "invalid" [(finding "invalid" $"record issue ($rec.issue) does not match the referenced issue ($issue_id)")] {issue: $issue_id, repo: $repo_name, required_class: $required_class, declared_class: $rec.blast_radius, evidence_required: $evidence_required})
    exit-with $v $json
  }
  let findings = (validate-record-semantics $rec {now: $now, description: $loaded.description, repo: $repo_name, required_class: $required_class, issue_state_type: $loaded.state_type})

  # 5. evidence
  let waived = (active-waivers $rec $now)
  let effective_required = ($evidence_required | where {|k| $k not-in $waived })
  let ev_findings = if $require_evidence and ($findings | is-empty) {
    let ref_sha = if ($ref != null) { $ref } else { ^git -C $root rev-parse $head | complete | get stdout | str trim }
    check-evidence (parse-evidence $loaded.comments) $repo_name $effective_required $ref_sha $any_ref
  } else { [] }

  let all = ($findings | append $ev_findings)
  let v = (make-verdict (verdict-status $all) $all {
    issue: $issue_id, repo: $repo_name, required_class: $required_class, declared_class: $rec.blast_radius,
    evidence_required: $effective_required, waived: $waived, record: $rec, paths: $paths
  })
  exit-with $v $json
}

# Print the parsed readiness record of an issue description as JSON.
def "main parse" [--file: path, --issue: string] {
  let text = if ($file != null) { open --raw $file } else if ($issue != null) { (linear-issue $issue).description | default "" } else { error make {msg: "give --file or --issue"} }
  let blocks = (fenced-blocks $text "readiness")
  if ($blocks | length) != 1 { error make {msg: $"expected exactly one readiness block, found ($blocks | length)"} }
  let rec = (parse-yaml-block ($blocks | first))
  if ($rec == null) { error make {msg: "readiness block is not a YAML mapping"} }
  let f = (validate-record-shape $rec)
  {record: $rec, findings: $f, scope_digest: (scope-digest $text)} | to json
}

# Print the scope digest of an issue description.
def "main digest" [--file: path, --issue: string] {
  let text = if ($file != null) { open --raw $file } else if ($issue != null) { (linear-issue $issue).description | default "" } else { error make {msg: "give --file or --issue"} }
  print (scope-digest $text)
}

def render-block [rec] {
  let ex = ($rec | get -o exceptions | default [])
  let lines = [
    "```readiness"
    $"contract: ($rec.contract)"
    $"issue: ($rec.issue)"
    $"state: ($rec.state)"
    $"blast_radius: ($rec.blast_radius)"
    "repos:"
  ] | append ($rec.repos | each {|r| $"  - ($r)" })
    | append [
      $"scope_digest: ($rec | get -o scope_digest | default '')"
      $"approved_by: ($rec | get -o approved_by | default '')"
      $"approved_at: ($rec | get -o approved_at | default '')"
      $"expires_at: ($rec | get -o expires_at | default '')"
    ]
    | append (if ($ex | is-empty) { ["exceptions: []"] } else { ["exceptions:"] | append ($ex | each {|e|
        [
          $"  - id: ($e.id)"
          $"    waives: [($e.waives | str join ', ')]"
          $"    owner: ($e.owner)"
          $"    expires_at: ($e.expires_at)"
          $"    approval: ($e.approval)"
          $"    follow_up: ($e.follow_up)"
        ] | append (if (($e | get -o reason) == null) { [] } else { [$"    reason: ($e.reason)"] })
      } | flatten) })
    | append (if (($rec | get -o notes) == null) { [] } else { [$"notes: ($rec.notes)"] })
    | append ["```"]
  $lines | str join "\n"
}

# Print a readiness block skeleton for a new issue.
def "main template" [--issue: string = "TEO-0000", --class: string = "local", --repos: string = ""] {
  if ($class not-in (class-names)) { error make {msg: $"unknown class ($class)"} }
  render-block {contract: $CONTRACT, issue: $issue, state: "draft", blast_radius: $class, repos: (if ($repos | str trim | is-empty) { ["Eugene3dotdev/<repo>"] } else { $repos | split row "," | each {|r| $r | str trim } }), exceptions: []}
}

# Approve: recompute the scope digest, set state ready, approved_at now and
# expires_at now + days, and print (or --write back to Linear) the description.
def "main stamp" [
  --issue: string
  --record: path           # offline: description file; result printed, never written to Linear
  --approved-by: string
  --days: int = 14
  --write                  # update the Linear issue description in place
  --now: string
] {
  if ($approved_by == null) { error make {msg: "--approved-by is required"} }
  if $days < 1 or $days > $MAX_VALIDITY_DAYS { error make {msg: $"--days must be 1..($MAX_VALIDITY_DAYS)"} }
  let now = if ($now == null) { now-utc } else { parse-ts $now }
  let loaded = if ($record != null) { {description: (open --raw $record), id: null} } else {
    if ($issue == null) { error make {msg: "give --issue or --record"} }
    let i = (linear-issue $issue); {description: ($i.description | default ""), id: $i.id}
  }
  let blocks = (fenced-blocks $loaded.description "readiness")
  if ($blocks | length) != 1 { error make {msg: $"expected exactly one readiness block, found ($blocks | length)"} }
  let rec = (parse-yaml-block ($blocks | first))
  if ($rec == null) { error make {msg: "readiness block is not a YAML mapping"} }
  let shape = (validate-record-shape $rec)
  if ($shape | is-not-empty) { error make {msg: $"record is invalid: ($shape | get message | str join '; ')"} }
  if ($issue != null) and ($rec.issue != $issue) { error make {msg: $"record issue ($rec.issue) does not match ($issue)"} }
  let stamped = ($rec
    | upsert state "ready"
    | upsert scope_digest (scope-digest $loaded.description)
    | upsert approved_by $approved_by
    | upsert approved_at (fmt-ts $now)
    | upsert expires_at (fmt-ts ($now + ($days * 1day))))
  let ls = ($loaded.description | lines)
  let start = ($ls | enumerate | where {|e| ($e.item | str trim) == "```readiness" } | get 0.index)
  let rest = ($ls | skip ($start + 1))
  let len = ($rest | enumerate | where {|e| ($e.item | str trim) starts-with "```" } | get 0.index)
  let new_desc = (($ls | first $start) | append (render-block $stamped | lines) | append ($rest | skip ($len + 1)) | str join "\n")
  if $write {
    if ($loaded.id == null) { error make {msg: "--write needs --issue (a Linear issue), not --record"} }
    let r = (linear-issue-update-description $loaded.id $new_desc)
    if not ($r | get -o issueUpdate.success | default false) { error make {msg: "Linear issueUpdate did not report success"} }
    print $"stamped ($stamped.issue): ready until ($stamped.expires_at), scope_digest ($stamped.scope_digest)"
  } else {
    print $new_desc
  }
}

# Record validation evidence on the Linear issue as a ```readiness-evidence comment.
def "main evidence" [
  --issue: string
  --kind: string
  --status: string = "pass"
  --ref: string            # git sha the evidence is for (default: HEAD of --repo-dir)
  --control-point: string
  --run: string            # URL of the CI run or log
  --note: string
  --repo-dir: path
  --repo: string
  --dry-run                # print the comment instead of posting
] {
  if ($issue == null or $kind == null or $control_point == null) { error make {msg: "--issue, --kind and --control-point are required"} }
  if ($kind not-in $EVIDENCE_KINDS) { error make {msg: $"unknown evidence kind ($kind); known: ($EVIDENCE_KINDS | str join ', ')"} }
  if ($status not-in $EVIDENCE_STATUSES) { error make {msg: $"status must be one of ($EVIDENCE_STATUSES | str join ', ')"} }
  let root = (git-root ($repo_dir | default (pwd)))
  let repo_name = ($repo | default (load-adapter $root).repo)
  let sha = if ($ref != null) { $ref } else { ^git -C $root rev-parse HEAD | complete | get stdout | str trim }
  let fp = (evidence-fingerprint $repo_name $kind $sha $status)
  let body = ([
    $"Readiness evidence for ($repo_name): **($kind)** = ($status) at `($sha)`."
    ""
    "```readiness-evidence"
    $"contract: ($CONTRACT)"
    $"repo: ($repo_name)"
    $"kind: ($kind)"
    $"status: ($status)"
    $"ref: ($sha)"
    $"control_point: ($control_point)"
    $"run: ($run | default '')"
    $"recorded_at: (fmt-ts (now-utc))"
    $"fingerprint: ($fp)"
  ] | append (if ($note == null) { [] } else { [$"note: ($note)"] }) | append ["```"] | str join "\n")
  if $dry_run { print $body; return }
  let i = (linear-issue $issue)
  let existing = (parse-evidence ($i | get -o comments.nodes | default []) | where fingerprint == $fp)
  if ($existing | is-not-empty) { print $"evidence already recorded on ($issue) \(fingerprint ($fp)\)"; return }
  let r = (linear-comment-create $i.id $body)
  if not ($r | get -o commentCreate.success | default false) { error make {msg: "Linear commentCreate did not report success"} }
  print $"recorded ($kind)=($status) for ($repo_name)@($sha) on ($issue): ($r | get -o commentCreate.comment.url | default '')"
}

# Post a file as a comment on a Linear issue (program notes, audit reports).
def "main comment" [--issue: string, --file: path, --dry-run] {
  if ($issue == null or $file == null) { error make {msg: "--issue and --file are required"} }
  let body = (open --raw $file)
  if $dry_run { print $body; return }
  let i = (linear-issue $issue)
  let r = (linear-comment-create $i.id $body)
  if not ($r | get -o commentCreate.success | default false) { error make {msg: "Linear commentCreate did not report success"} }
  print $"commented on ($issue): ($r | get -o commentCreate.comment.url | default '')"
}

# ---------------------------------------------------------------------------
# discovery and audit
# ---------------------------------------------------------------------------

def discover-paths [root] {
  let files = (tracked-files $root)
  $EXECUTION_PATHS | each {|pat|
    $files | where {|f| glob-match $pat.glob $f } | each {|f| {kind: $pat.kind, path: $f} }
  } | flatten | uniq-by path | sort-by path
}

def discover-report [root, adapter] {
  let found = (discover-paths $root)
  let registered = ($adapter.control_points | get path)
  let ignored = ($adapter | get -o ignore_paths | default [])
  let rows = ($found | each {|d|
    let status = if ($d.path in $registered) { "registered" } else if ($ignored | any {|g| glob-match $g $d.path }) { "ignored" } else { "unregistered" }
    $d | insert status $status
  })
  let missing_cp = ($adapter.control_points | where {|cp| not ([$root $cp.path] | path join | path exists) })
  {paths: $rows, unregistered: ($rows | where status == "unregistered"), missing_control_points: $missing_cp}
}

# List execution paths of a repository and compare with its adapter.
def "main discover" [--repo-dir: path, --json] {
  let root = (git-root ($repo_dir | default (pwd)))
  let adapter = (load-adapter $root)
  let rep = (discover-report $root $adapter)
  if $json { print ($rep | to json); } else {
    print $"execution paths in ($adapter.repo):"
    for r in $rep.paths { print $"  [($r.status)] ($r.kind) ($r.path)" }
    for m in $rep.missing_control_points { print $"  [missing] control point ($m.id) → ($m.path) does not exist" }
  }
  if ($rep.unregistered | is-not-empty) or ($rep.missing_control_points | is-not-empty) { exit 1 }
}

def gate-marker-ok [root, cp] {
  let file = ([$root $cp.path] | path join)
  if not ($file | path exists) { return false }
  let marker = ($cp | get -o marker | default "readiness.nu check")
  open --raw $file | str contains $marker
}

def github-required-checks [repo: string, branch: string, token: string] {
  let headers = ["Authorization" $"Bearer ($token)" "Accept" "application/vnd.github+json" "X-GitHub-Api-Version" "2022-11-28"]
  let rules = (try { http get --full --allow-errors --headers $headers $"($GITHUB_API)/repos/($repo)/rules/branches/($branch)" } catch {|e| {status: 0, body: $e.msg} })
  let from_rules = if $rules.status == 200 {
    $rules.body | where type == "required_status_checks" | each {|r| $r | get -o parameters.required_status_checks | default [] | get context } | flatten
  } else { [] }
  let classic = (try { http get --full --allow-errors --headers $headers $"($GITHUB_API)/repos/($repo)/branches/($branch)/protection/required_status_checks" } catch {|e| {status: 0, body: $e.msg} })
  let from_classic = if $classic.status == 200 { $classic.body | get -o contexts | default [] } else { [] }
  let prot = (try { http get --full --allow-errors --headers $headers $"($GITHUB_API)/repos/($repo)/branches/($branch)/protection" } catch {|e| {status: 0, body: $e.msg} })
  let protected = ($prot.status == 200) or (($rules.status == 200) and ($rules.body | is-not-empty))
  {protected: $protected, required: ($from_rules | append $from_classic | uniq), rules_status: $rules.status, protection_status: $prot.status}
}

def locate-repo [root_dir, entry] {
  let short = ($entry.repo | split row "/" | last)
  let owner = ($entry.repo | split row "/" | first)
  let candidates = [
    ($entry | get -o local_path | default "")
    ([$root_dir $short] | path join)
    ([$root_dir "github.com" $owner $short] | path join)
    ([$root_dir $owner $short] | path join)
  ] | where {|p| ($p | is-not-empty) and ($p | path exists) }
  if ($candidates | is-empty) { null } else { $candidates | first }
}

def audit-repo [entry, root_dir, canonical_sha: string, github: bool, token: string] {
  let dir = (locate-repo $root_dir $entry)
  if ($dir == null) {
    return {repo: $entry.repo, located: false, gaps: [$"clone not found under ($root_dir)"], adapter_ok: false, lock_ok: false, canonical_ok: false, missing_control_points: [], unregistered: [], protection: null}
  }
  let root = (try { git-root $dir } catch { null })
  if ($root == null) { return {repo: $entry.repo, located: true, gaps: [$"($dir) is not a git repository"], adapter_ok: false, lock_ok: false, canonical_ok: false, missing_control_points: [], unregistered: [], protection: null} }
  let head = (^git -C $root rev-parse --short HEAD | complete | get stdout | str trim)
  let adapter = (try { {ok: true, a: (load-adapter $root)} } catch {|e| {ok: false, msg: $e.msg} })
  if not $adapter.ok {
    return {repo: $entry.repo, located: true, head: $head, gaps: [$"adapter: ($adapter.msg)"], adapter_ok: false, lock_ok: false, canonical_ok: false, missing_control_points: [], unregistered: [], protection: null}
  }
  let a = $adapter.a
  mut gaps = []
  if $a.repo != $entry.repo { $gaps = ($gaps | append $"adapter declares repo ($a.repo), registry expects ($entry.repo)") }
  if $a.contract_version != $entry.contract_version { $gaps = ($gaps | append $"adapter contract ($a.contract_version) differs from registry expectation ($entry.contract_version)") }
  # lock and validator drift
  let vfile = ([$a._dir "readiness.nu"] | path join)
  let lfile = (lock-path $a._dir)
  let is_canonical = (($entry | get -o canonical | default false) == true)
  let lock = if ($lfile | path exists) { try { open --raw $lfile | from yaml } catch { null } } else { null }
  let lock_ok = if $is_canonical { true } else if ($lock == null) { false } else {
    ($lock | get -o lock) == $LOCK_SCHEMA and ($vfile | path exists) and (($lock | get -o validator_sha256) == (validator-sha $vfile))
  }
  let canonical_ok = if $is_canonical { (validator-sha $vfile) == $canonical_sha } else { ($vfile | path exists) and ((validator-sha $vfile) == $canonical_sha) }
  if not $lock_ok { $gaps = ($gaps | append "lock.yaml missing or its validator_sha256 does not match the vendored readiness.nu") }
  if not $canonical_ok { $gaps = ($gaps | append "vendored readiness.nu differs from the canonical validator (re-vendor from dotfiles)") }
  # control points
  let expected_ids = ($entry | get -o control_points | default [])
  let adapter_ids = ($a.control_points | get id)
  for id in $expected_ids { if ($id not-in $adapter_ids) { $gaps = ($gaps | append $"registry control point ($id) is not declared by the adapter") } }
  for id in $adapter_ids { if ($id not-in $expected_ids) { $gaps = ($gaps | append $"adapter control point ($id) is not registered in the registry") } }
  let rep = (discover-report $root $a)
  for m in $rep.missing_control_points { $gaps = ($gaps | append $"control point ($m.id) path ($m.path) does not exist") }
  for cp in ($a.control_points | where enforces == true) {
    if not (gate-marker-ok $root $cp) { $gaps = ($gaps | append $"enforcing control point ($cp.id) \(($cp.path)\) does not invoke the readiness gate") }
  }
  for u in $rep.unregistered { $gaps = ($gaps | append $"unregistered execution path: ($u.kind) ($u.path)") }
  let enforcing = ($a.control_points | where enforces == true)
  if ($enforcing | is-empty) { $gaps = ($gaps | append "adapter declares no enforcing control point") }
  # branch protection
  let protection = if $github {
    let branches = ($entry | get -o protected_branches | default [($entry | get -o default_branch | default "main")])
    $branches | each {|b|
      let p = (github-required-checks $entry.repo $b $token)
      let wanted = ($a.control_points | where enforces == true | each {|cp| $cp | get -o required_check } | compact)
      let missing = ($wanted | where {|w| $w not-in $p.required })
      {branch: $b, protected: $p.protected, required: $p.required, missing_required_checks: $missing, rules_status: $p.rules_status, protection_status: $p.protection_status}
    }
  } else { null }
  if $github {
    for p in $protection {
      if not $p.protected { $gaps = ($gaps | append $"branch ($p.branch) is not protected \(rules HTTP ($p.rules_status), protection HTTP ($p.protection_status)\)") }
      for m in $p.missing_required_checks { $gaps = ($gaps | append $"branch ($p.branch) does not require status check `($m)`") }
    }
  }
  {
    repo: $entry.repo, located: true, head: $head, adapter_ok: true, lock_ok: $lock_ok, canonical_ok: $canonical_ok,
    class: ($entry | get -o class), contract: $a.contract_version,
    control_points: ($a.control_points | each {|cp| {id: $cp.id, enforces: $cp.enforces, path: $cp.path} }),
    missing_control_points: ($rep.missing_control_points | get id), unregistered: ($rep.unregistered | get path),
    exempt_actors: ($a | get -o exempt_actors | default []), protection: $protection, gaps: $gaps
  }
}

def audit-markdown [report] {
  let rows = ($report.repositories | each {|r|
    let status = if ($r.gaps | is-empty) { "covered" } else { "GAP" }
    $"| ($r.repo) | ($r | get -o head | default '-') | ($r | get -o class | default '-') | ($r | get -o contract | default '-') | ($status) | ($r.gaps | length) |"
  })
  let details = ($report.repositories | where {|r| $r.gaps | is-not-empty } | each {|r|
    ([$"### ($r.repo)"] | append ($r.gaps | each {|g| $"- ($g)" })) | str join "\n"
  })
  ([
    $"## Readiness coverage audit \(($CONTRACT)\)"
    ""
    $"Generated ($report.generated_at) from registry `($report.registry)`; canonical validator sha256 `($report.canonical_sha256 | str substring 0..<12)…`."
    ""
    "| repository | head | class | contract | status | gaps |"
    "|---|---|---|---|---|---|"
  ] | append $rows | append [""] | append $details | append [
    ""
    $"Total gaps: ($report.total_gaps). Repositories covered: ($report.covered)/($report.repositories | length)."
  ]) | str join "\n"
}

# Compare the registry with live repository configuration.
def "main audit" [
  --registry: path         # registry.yaml (default: next to this validator)
  --root: path             # directory holding the clones (flat <name>/ or ghq github.com/<owner>/<name>/ layout)
  --github                 # also verify branch protection and required checks through the GitHub API (needs GITHUB_TOKEN or READINESS_AUDIT_TOKEN)
  --json                   # machine-readable report
  --out: path              # write the markdown report here
  --post-issue: string     # post the markdown report as a Linear comment on this issue
] {
  let reg_path = ($registry | default ([($SELF | path dirname) "registry.yaml"] | path join))
  let reg = (open --raw $reg_path | from yaml)
  if (($reg | get -o registry) != $REGISTRY_SCHEMA) { error make {msg: $"($reg_path): registry schema must be ($REGISTRY_SCHEMA)"} }
  let root_dir = ($root | default ($SELF | path dirname | path dirname | path dirname))
  let canonical_entry = ($reg.repositories | where {|r| ($r | get -o canonical | default false) == true } | get -o 0)
  if ($canonical_entry == null) { error make {msg: "registry has no canonical repository entry"} }
  let canonical_sha = (validator-sha $SELF)
  let token = ($env | get -o READINESS_AUDIT_TOKEN | default ($env | get -o GITHUB_TOKEN | default ""))
  if $github and ($token | is-empty) { error make {msg: "--github needs READINESS_AUDIT_TOKEN or GITHUB_TOKEN"} }
  let repos = ($reg.repositories | each {|e| audit-repo ($e | upsert contract_version ($e | get -o contract_version | default $reg.contract_version)) $root_dir $canonical_sha $github $token })
  let total = ($repos | each {|r| $r.gaps | length } | math sum)
  let report = {
    contract: $CONTRACT, registry: ($reg_path | path basename), generated_at: (fmt-ts (now-utc)), canonical_sha256: $canonical_sha,
    github_checked: $github, repositories: $repos, total_gaps: $total, covered: ($repos | where {|r| $r.gaps | is-empty } | length)
  }
  let md = (audit-markdown $report)
  if ($out != null) { $md | save --force $out }
  if $json { print ($report | to json) } else { print $md }
  if ($post_issue != null) {
    let i = (linear-issue $post_issue)
    let r = (linear-comment-create $i.id $md)
    if not ($r | get -o commentCreate.success | default false) { error make {msg: "Linear commentCreate did not report success"} }
    print $"posted audit to ($post_issue)"
  }
  if $total > 0 { exit 1 }
}

# Verify or refresh the lock that pins the vendored validator.
def "main lock" [
  --dir: path              # directory holding readiness.nu and lock.yaml (default: this file's directory)
  --update                 # rewrite lock.yaml from the current file
  --source-commit: string  # canonical dotfiles commit the copy was taken from (recorded with --update)
] {
  let d = ($dir | default ($SELF | path dirname))
  let vfile = ([$d "readiness.nu"] | path join)
  if not ($vfile | path exists) { error make {msg: $"no readiness.nu in ($d)"} }
  let sha = (validator-sha $vfile)
  let lfile = (lock-path $d)
  if $update {
    let existing = if ($lfile | path exists) { try { open --raw $lfile | from yaml } catch { {} } } else { {} }
    let text = ([
      "# Pins the vendored copy of the canonical readiness validator. Regenerate"
      "# with `nu .readiness/readiness.nu lock --update` after re-vendoring;"
      "# `readiness.nu audit` in dotfiles reports any copy whose sha differs from"
      "# the canonical file."
      $"lock: ($LOCK_SCHEMA)"
      $"contract_version: ($CONTRACT)"
      $"validator_sha256: ($sha)"
      $"source: ($existing | get -o source | default 'Eugene3dotdev/dotfiles')"
      $"source_path: ($existing | get -o source_path | default 'readiness/readiness.nu')"
      $"source_commit: ($source_commit | default ($existing | get -o source_commit | default 'unknown'))"
      $"vendored_at: (fmt-ts (now-utc))"
    ] | str join "\n") + "\n"
    $text | save --force $lfile
    print $"wrote ($lfile) \(sha256 ($sha | str substring 0..<12)…\)"
    return
  }
  if not ($lfile | path exists) { print $"lock: no lock.yaml in ($d)"; exit 1 }
  let lock = (open --raw $lfile | from yaml)
  if (($lock | get -o lock) != $LOCK_SCHEMA) { print $"lock: schema must be ($LOCK_SCHEMA)"; exit 1 }
  if (($lock | get -o contract_version) != $CONTRACT) { print $"lock: contract_version ($lock | get -o contract_version) differs from validator ($CONTRACT)"; exit 1 }
  if (($lock | get -o validator_sha256) != $sha) { print $"lock: readiness.nu sha256 ($sha) does not match lock ($lock | get -o validator_sha256)"; exit 1 }
  print $"lock ok: ($CONTRACT) ($sha | str substring 0..<12)… from ($lock | get -o source | default '?')@($lock | get -o source_commit | default '?')"
}

# Contract constants, for the tests that keep the YAML contract and this file in step.
def "main contract" [] {
  {
    contract: $CONTRACT, supported_record_contracts: $SUPPORTED_RECORD_CONTRACTS, states: $STATES, classes: $CLASSES,
    evidence_kinds: $EVIDENCE_KINDS, evidence_statuses: $EVIDENCE_STATUSES, record_keys: $RECORD_KEYS, record_required: $RECORD_REQUIRED,
    ready_required: $READY_REQUIRED, exception_keys: $EXCEPTION_KEYS, max_validity_days: $MAX_VALIDITY_DAYS,
    default_validity_days: $DEFAULT_VALIDITY_DAYS, execution_paths: $EXECUTION_PATHS
  } | to json
}

# Print the Linear issue identifier a change references (same resolution as check).
def "main issue" [--title: string, --branch: string, --body: string, --repo-dir: path, --head: string = "HEAD"] {
  let root = (git-root ($repo_dir | default (pwd)))
  let adapter = (load-adapter $root)
  let prefix = ($adapter | get -o issue_prefix | default $DEFAULT_ISSUE_PREFIX)
  let event = (github-event)
  let pr = if ($event == null) { null } else { $event | get -o pull_request }
  let head_msg = (^git -C $root log -1 --format=%B $head | complete | get stdout)
  let sources = [
    (issue-ref-in $title $prefix)
    (issue-ref-in $branch $prefix)
    (issue-ref-in $body $prefix)
    (if ($pr == null) { null } else { issue-ref-in ($pr | get -o title) $prefix })
    (if ($pr == null) { null } else { issue-ref-in ($pr | get -o head.ref) $prefix })
    (if ($pr == null) { null } else { issue-ref-in ($pr | get -o body) $prefix })
    (issue-ref-in $head_msg $prefix)
  ] | compact
  if ($sources | is-empty) { print -e $"no ($prefix)-<n> issue reference found"; exit 1 }
  print ($sources | first)
}
