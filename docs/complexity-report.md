# Function complexity reporting

Use `sanctifier complexity <path>` on a Rust source file or directory of
Rust files. The command reuses the existing Sanctifier `syn` AST scoring
engine and adds per-function thresholds, text and machine-readable JSON.

```sh
sanctifier complexity contracts/my-token/src
sanctifier complexity contracts/my-token/src --format json
sanctifier complexity contracts/my-token/src --max-cyclomatic 8 \
  --max-nesting 3 --max-function-lines 40 --max-params 5 --fail-on-exceed
```

The report includes source path, function name, cyclomatic complexity,
maximum nesting, physical function length, parameters and warnings.
JSON includes a schema version, applied limits and per-file summary.
`--fail-on-exceed` prints the complete report before returning nonzero,
so CI can retain useful diagnostics when a limit is exceeded.

## Methodology and limits

Cyclomatic complexity begins at 1 and counts `if`, loops, additional
`match` arms and short-circuit boolean branches. Nesting tracks visited
conditionals and loops. Function length uses original `syn` source
spans, correcting the legacy token-string LOC=1 issue. Signature parameter
counts include `self` when present. These are **syntactic proxies**, not
measured gas fees, instruction counts, wall time, or proof of a vulnerability;
macro-expanded behavior may differ.

Defaults warn above CC 10, nesting 4, length 50 physical lines or
parameters 5. All thresholds are independently configurable.
Directory scanning skips symlinks and the generated directories
`.git`, `target` and `node_modules`. Missing inputs, read errors and
Rust parse errors return failure rather than silently presenting zero
complexity. Only public free functions and methods are analyzed by the
existing core visitor.
