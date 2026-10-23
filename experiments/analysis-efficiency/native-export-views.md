# Native export questions over retained Evidence

Issue #6900: retrieve the export count and every declared version/alias of two
named exports, verify a missing-name query within the examined table, and export
the complete Evidence. The previous workflow returns the complete export table
to the client. The selected workflow returns a summary, queries matching rows,
and keeps the same complete parent accessible through Evidence export.

## Pinned inputs and correctness

- Baseline: `9fd78a74f84a8e924bd58e7deaf5934bfb24f53c` (main, including the ELF
  unknown-coverage fix #6827). Candidate and experiment driver:
  `fd23b89b0b1727b483050025e7af344145c1fd91`.
- Linux x86-64, Node 24.22.1, npm 11.16.0; package and kernel versions are in
  [the receipt](native-export-views.json). Each runtime's compiled files and
  entrypoints were SHA-256 checked before and after every task. Source checkouts
  were clean when frozen. Later reporting changes do not change that measured
  implementation revision.
- `/usr/lib/x86_64-linux-gnu/libLLVM-14.so.1`: 109,967,296 bytes, 44,459 exports,
  SHA-256 `436887791de0478d72c8323be99df69d6d0cf82745e5abec79d5e0374f4df560`.
  Query `LLVMContextCreate` and `LLVMContextDispose`: two rows.
- `/usr/lib/x86_64-linux-gnu/libc.so.6`: 1,926,232 bytes, 3,025 exports,
  SHA-256 `6b4a45352fd0c540a9c7c718f35ce8c8e46a4e482f9d3885a910c32d1a0e1421`.
  Query `malloc` and `memcpy`: three rows, including both `memcpy` versions and
  the IFUNC declaration. No runtime address or execution claim is made.

The independent oracle combines GNU `readelf` 2.40 dynamic symbol facts with
direct ELF64 little-endian mapping of version indices and hidden flags in
[native-export-oracle.py](native-export-oracle.py). It checks the full export
count and each selected row, including its index in the original report. All six
tasks for each artifact produced identical answers, complete parent Evidence IDs
and source report digests. Target bytes were unchanged. This oracle is qualified
for these ELF64 little-endian artifacts and selected ASCII names; it does not
establish real PE performance or arbitrary ELF encoding coverage.

## Measured completed tasks

Three alternating pairs per artifact, serial execution, fresh stdio client,
server and HOME per task; Node compile cache disabled. Retained page queries
reuse their parent within the task. OS file caches were not flushed, and there
was no separate warm-server cohort. All twelve tasks passed without resource
stops, OOM events, process-limit events or owned payload processes remaining.

| Artifact / workflow | Calls | Reply bytes | Projected tokens | Elapsed seconds, median [range] | Family CPU seconds, median [range] | Kernel family peak MiB, median [range] |
| ------------------- | ----: | ----------: | ---------------: | ------------------------------- | ---------------------------------- | -------------------------------------- |
| libc / complete     |     2 |   1,653,409 |          289,912 | 16.132 [15.726–32.588]          | 15.564 [15.332–28.761]             | 1,008.8 [971.4–1,013.4]                |
| libc / selected     |     5 |      25,946 |           58,253 | 17.646 [17.239–20.287]          | 16.108 [15.866–19.899]             | 938.5 [938.3–950.2]                    |
| LLVM / complete     |     2 |  28,986,221 |        4,355,448 | 89.863 [87.839–153.857]         | 85.856 [84.154–151.773]            | 1,870.2 [1,795.2–1,927.5]              |
| LLVM / selected     |     4 |      19,689 |           57,346 | 21.477 [20.463–23.885]          | 19.610 [19.483–20.138]             | 1,266.1 [1,239.9–1,297.9]              |

These are scripted SDK tasks, with the full 220-tool directory discovered once.
The `cl100k_base` estimate (tiktoken 0.12.0) counts a fixed task description,
every tool name/description/input schema once, all call arguments and text
replies, including Evidence export. It excludes host injection and history
replay. No actual model ran; these are neither billable usage nor investigation
quality measurements. The SDK also receives output schemas: the entire raw
catalog costs 812,145 tokens before and 815,054 after if a host injects all of it.
That cost is reported separately. With only the three task tools injected,
estimated task totals are 238,857 → 7,198 for libc and 4,304,393 → 6,291 for LLVM.
Tokenizer work ran separately from the twelve task measurements.

Both libc lanes used a 10 MiB transport budget. Both LLVM timing lanes used
64 MiB to permit a complete-response comparison. Separate final probes at
10 MiB observed the baseline complete call return `resource_constraint`, while
the selected task completed. The failed complete task is preserved and excluded
from successful-task timing statistics. These boundary probes establish behavior,
not an additional performance pair.

The selected libc task has extra calls and is slightly slower at the median.
LLVM has substantial observed task savings, but the result does not identify a
faster native parser: both workflows still analyze and retain the full table.
The `inspect` RPC includes analysis, Evidence, validation and delivery; no
internal phase attribution was measured. First selected-page calls in the first
pairs took about 243–246 ms, while later retained calls took about 9–23 ms.
The weak cache holds validation of an exact immutable retained report, not live
filesystem state. Unfiltered pages slice the original order; filtered pages scan
the retained rows and preserve every matching alternative.

Resources: one CPU's aggregate quota (100%), clients/servers bound to CPUs 0–1,
observer initially on CPU 15; 3 GiB early stop, 4 GiB hard limit, no swap, 192
tasks. The guard's affinity field records initial placement; it does not describe
the wrapper's child affinity override. A live cgroup/process observation confirmed
the quota and override. Family CPU and peak memory come from kernel cgroup
counters at payload exit while an observer remains alive. Cleanup was verified
at that point. Final whole-scope counters became unavailable after scope removal
and remain null; no final whole-scope counter verification is claimed. Timing
includes discovery, runtime hashing, client checks, Evidence export and receipts.
Variation in the slower complete samples is retained in the ranges.

## Reproduction and validation

Run from the candidate checkout with its locked dependencies and pinned Node.
Freeze a clean built runtime with `scripts/rea.mjs`, `package.json`, `dist/` and
dependencies; record source revision plus SHA-256 for compiled files and
entrypoints as demonstrated by the committed receipt's runtime identities.

```sh
python3 experiments/analysis-efficiency/native-export-oracle.py \
  /usr/lib/x86_64-linux-gnu/libLLVM-14.so.1 LLVMContextCreate LLVMContextDispose \
  > /absolute/path/oracle.json
python3 experiments/analysis-efficiency/resource-run.py --observe-payload-exit -- \
  node experiments/analysis-efficiency/native-export-views.mjs \
  --runtime /absolute/path/runtime --identity /absolute/path/runtime/runtime-identity.json \
  --oracle /absolute/path/oracle.json --output /absolute/path/unused-receipt-directory \
  --lane selected --buffer 67108864
```

Use `--lane complete` against the baseline. Repeat three pairs in alternating
order. The JSON receipt records every executed command, runtime binding,
per-call timings/bytes, results and SHA-256 of raw reports/catalogs/transcripts/
Evidence/resource logs. Its `cohort` manifest records driver and guard hashes.
Generate token estimates with `native-export-costs.py --cohort COHORT --output
OUTPUT CASE...`, using tiktoken 0.12.0. Raw local receipts are under
`/tmp/rea-perf-native-exports-20261023/`; they are not committed binaries or
portable artifact downloads. `final-cohort/index.json` and `manifest.json` bind
the twelve cases. Preserve these files together when rerunning the cost script.

Executed functional validation of the measured implementation:

- 47 selected tests passed: parser, export views, MCP schemas/retention preflight,
  and actual public CLI/stdio workflows for PE and ELF fixtures. Source deletion
  after retention still permits equivalent offline CLI and retained MCP views.
- `npm run check`, documentation generation/check and test-discovery verification
  passed; 2,180 tests were discovered exactly once.
- Real LLVM public CLI summary → full Evidence bundle → offline selected view
  was also checked; the complete bundle retains 44,459 exports.
- Earlier assertion spelling mistakes, an architecture-boundary test placement
  violation and a concurrent-worker timeout are retained in the local logs.
  The test was moved to the native layer; final bounded tests and static gates
  passed. No real Hopper/Ghidra/IDA behavior changed or was qualified here.

Partial/unsupported source coverage, duplicate names/versions, PE ordinal-only
exports, forwarded exports, field projection, malformed retained input and older
encoding metadata are covered by deterministic boundary regressions. Those tests
supplement the real ELF tasks; they are not real PE provider measurements.
