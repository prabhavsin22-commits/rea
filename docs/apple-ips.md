# Apple IPS crash reports

`inspect_apple_ips` / `inspect-apple-ips` answers whether one selected local
Apple `.ips` file is a crash report (`bug_type` string `"309"`), which process,
exception, and termination facts that report records, which threads and
`usedImages` rows it lists, and which documented crash classes its strings
match. It reads the file without executing a target and does not require Xcode,
atos, a disassembler, or pwntools.

```bash
rea inspect-apple-ips /absolute/path/to/report.ips --json
```

The CLI resolves relative paths against the caller's working directory. MCP
requires an absolute filesystem path and preserves that exact selection:

```json
{
  "name": "inspect_apple_ips",
  "arguments": { "path": "/artifacts/report.ips" }
}
```

## Observations

The inline Evidence result contains the artifact path, SHA-256, and byte length.
`metadata` is the first-line JSON object. `bug_type` stays a string. The crash
body is parsed only when that string is `"309"`. Other types, including `"288"`
stackshots, return no crash result.

`process`, `exception`, `termination`, `faulting_thread`, `threads`, and
`images` reproduce documented body fields when present. Integers keep their
decimal literals and a hexadecimal form, including arm64e registers above
2^53. Frame roles follow physical frame depth: the top frame of the faulting
thread is `faulting_instruction`, the top frame of every other thread is that
thread's sampled `current_instruction`, and deeper frames are
`return_address`. Rows marked `inline` share the address of the frame below
them. When the report records no `faultingThread`, top frames are `unknown`.
`process.os_version` keeps the producer's dictionary (`train`, `build`,
`release_type`, `is_embedded`) or the older string form. Image UUIDs are uppercase 8-4-4-4-12; an all-zero UUID
or a missing `arch` is `uuid_unknown`. Image `source` letters keep their
documented meaning (`P` process, `S` shared cache, `C` shared cache library,
`K` kernel, `U` kernel cache, `T` kernel text exec, `A` absolute). Keys the
documentation does not list remain in `unlisted_keys` or `unlisted_body_keys`.

A present value whose JSON type differs from the documented one is never read
as absent: it is listed in `coverage.type_mismatches` with its path, the
expected type, and the observed type, and `coverage.status` becomes
`partial`. A crash body without `threads` or `usedImages` is also `partial`.

`classification` matches only documented SIGKILL codes (compared by their
canonical hexadecimal form), `EXC_GUARD` subtypes,
pointer-authentication suffixes, and dyld missing-library strings. A report
that matches none of those rules is `unclassified`.

Opened Mach-O and dSYM UUID joins remain unobserved. Symbol names printed
inside the report are recorded claims and are not verified. Linux ELF cores
use the separate [recorded crash](recorded-crashes.md) workflow.

## Limits and failures

The selected file is limited to 1 MiB by default (16 MiB maximum). At most 256
threads, 8192 frames, 1024 `usedImages` rows, and 16384 `threadState`
register slots are examined by default (4096 / 65536 / 4096 / 262144
maximum). Budgets are checked before each row is parsed, and body members the
report does not interpret are syntax-checked without being kept. Fixed
allowances bound JSON nesting (64 levels), unlisted key names per object
(1024), and `termination.reasons` entries (256). Malformed metadata, a
truncated crash body, invalid UTF-8, a NUL in the text, and exhausted budgets
fail without partial success.

This workflow does not execute a target, launch atos, or search for dSYMs.
