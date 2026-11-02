# Working on wekatester

`wekatester` is built, not edited: `./build` assembles it from `src/`, and both are committed. Edit `src/`, run `./build`, then run the suite (`bash tests/test_wekatester.sh`); both need bash 4.4 or later first in PATH. `./build` also writes `hostlist.example.csv` from the built tool's own template. The suite tests the built `wekatester`, and fails while it differs from what `./build` makes of `src/`. One suite runs at a time per host: a second one refuses, naming the first (the lock is `/tmp/wekatester-suite.lock`, or `SUITE_LOCK`). `SUITE_ONLY=<regex>` runs only the tests whose description matches and counts the rest as skipped; a pattern that matches nothing fails. A suite stopped by `timeout` prints `TIMEOUT after N s` with the counts so far and exits 124.

- `src/wekatester.sh`: the defaults, usage, option parsing and `main`, and where each module goes in.
- `src/sh/*.sh`: the rest of the bash, one module per part of a run: `base` (logging, the ssh transport, prompts), `awk` (the awk library and `awkrun`), `fiojson` (fio's JSON), `calibrate` (`-a`), `preflight` (reachability, mount mode, filesystem groups), `connect` (fio servers, limits, logins, teardown), `probe` (worker facts, engine tests, cpu pinning), `layout` (the capacity check, layout jobs), `hosts` (host files), `stage`, and `run` (the run, the dry run's report, the bundle and summary).
- `src/awk/lib/*.awk`: the awk library, in the order `awkrun` prepends it.
- `src/awk/<function>.awk`: every awk program longer than one line, named for the function that runs it (`<function>.<role>.awk` where one runs several).

In a `.sh` file `./build` reads two directives; an `.awk` file goes in as it is.

- A line `#@include <path>` becomes that file under `src/`, recursively.
- `#@awk <name>`, inside an awk program's single quotes and one to a line, becomes `src/awk/<name>.awk`: its first line takes the marker's place, each later line is indented like the marker's own line (an empty one stays empty), and every `'` becomes `'\''`, so the program stays one bash string. The marker goes right after the opening quote, or alone on the next line at the program's indent.

`./build` stops, naming the problem and leaving the target alone, on:

- a file it cannot read, or an awk file with no text;
- an include cycle;
- a second directive on a line, or anything else that looks like one;
- a directive left in the assembly (an include not named `.sh` comes in as it is);
- a program line ending in a backslash: `cal_evidence`'s program sits inside an unquoted heredoc, where bash would join it to the next line;
- a directory as the target;
- an assembly `bash -n` rejects, which it keeps as `<target>.rejected`.

The awk has to run the same under gawk and mawk, so every program keeps to a few conventions.

- `BEGIN` only, with its data on `ARGV`: `-v` would put a value through awk's escape processing. `awk_fail` exits from anywhere, which only `BEGIN` makes safe.
- `LC_ALL=C`, for byte order whatever the locale. Files are read whole by `readlines`, with universal newlines, and written back joined by `\n`.
- Byte counts are printed with `%.0f`.
- A comparison or `?:` inside a `print` list is parenthesized (`>` there is a redirection). No program variable named after a gawk built-in such as `RT` or `NR`.
- At most 50 parameters and locals per function, and never `A[k] = (k in A) ? ...` (mawk creates `A[k]` before the test).
- A line at a time, never a whole file in one string: `substr` and appends on a long string are quadratic in mawk.
- Files under `src/awk/` may contain apostrophes. A one-line program written inline in a `.sh` file sits inside bash single quotes, so it never contains one: write `\047`.
