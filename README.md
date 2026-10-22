# logchecker

> **Experimental.** This is a new rewrite and has not seen production
> use yet. Expect bugs, and don't rely on it in place of the
> originals. While this _is_ byte-for-byte identical to the original,
> bugs can happen.

A single static binary that replaces [OPSnet/Logchecker](https://github.com/OPSnet/Logchecker)
(PHP).

It scores EAC, XLD and whipper rip logs and verifies their checksums. Scores, details,
HTML output and checksum verdicts are identical to the originals. The command-line syntax is
its own.

It tracks Logchecker's `master` branch (currently
[`ca56547`](https://github.com/OPSnet/Logchecker/commit/ca56547)), not the 0.14.4 release.
Since 0.14.4, upstream checks checksums natively instead of calling the Python checkers
([`0498639`](https://github.com/OPSnet/Logchecker/commit/0498639f4aba65cccb012eaa4bac9e7d5e388f55)),
and the verdicts changed: an EAC log with several entries now gets the verdict of its worst
entry, where 0.14.4 said `checksum_ok` if any entry passed.

## Usage

```
logchecker analyze [--html] [--no_text] [--json] <file> [<out_file> [<details>]]
logchecker decode <file> [<out_file>]
logchecker translate [-l|--language <code>] <file> [<out_file>]

Global options: --ansi, --no-ansi, -V/--version, -h/--help
```

| Command     | Replaces                         | Does                                                       |
|-------------|----------------------------------|------------------------------------------------------------|
| `analyze`   | `logchecker analyze`             | Score a log, list the deductions, optionally write the HTML log |
| `decode`    | `logchecker decode`              | Detect the log's text encoding and convert it to UTF-8     |
| `translate` | `logchecker translate`           | Translate a non-English EAC log to English                 |

`analyze` (also spelt `analyse`) prints the ripper, version, language, score, checksum state,
deductions and the log text. `--json` prints the details as JSON instead, `--no_text` leaves out
the log text, and `--html` prints the log as HTML. With `<out_file>`, the HTML log is written
there and nothing is printed unless `--json` is given; `<details>` gets the details JSON. To read
a log from a pipe, pass `/dev/stdin` as `<file>`.

`decode` and `translate` print the converted log, or write it to `<out_file>`. `translate`
detects the log's language unless `-l` names it.

Colour is used when stdout is a terminal and `NO_COLOR` is unset. `--ansi` or `--no-ansi`
overrides that.

The HTML log (`--html` and `<out_file>`) is not escaped, as upstream's isn't: text from the log,
such as the drive name, can contain HTML tags. Sanitise it before showing it in a browser.

## Building

Requirements: a recent Rust toolchain (edition 2024).

Or use [devenv](https://devenv.sh): `devenv shell` (or direnv with `.envrc`) provides stable Rust with
the aarch64 musl target, static glibc, Python for `scripts/`, qemu-user and cargo-fuzz. Every
command below works in it as written, and `fuzz` runs `cargo fuzz` with a nightly toolchain.

```
cargo build --release
```

`.cargo/config.toml` builds for `x86_64-unknown-linux-gnu` with `+crt-static`. The binary is
written to `target/x86_64-unknown-linux-gnu/release/logchecker` and is fully statically linked.

Other architectures build against musl, which is also fully static. The config links musl
targets with `rust-lld`, so no cross C toolchain is needed:

```
rustup target add aarch64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

To test on the build machine, run the tests under qemu user-mode emulation:

```
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64 \
    cargo test --release --target aarch64-unknown-linux-musl
```

`tests/cli.rs` starts the binary directly, so its tests fail with "Exec format error" unless
qemu is registered with binfmt_misc.

## Testing

```
cargo test --release
```

`tests/upstream.rs` contains the upstream test suites, ported:

- **Logchecker:** the phpunit tests, run against all 44 original logs. Details must match and
  the HTML must be byte-identical.
- **Checksums:** the EAC, XLD and dispatch checksum tests.
- **Decoding and translation:** the decode tests and the translator tests.
- **The Python checkers:** the test tables from eac_logchecker.py and xld_logchecker.py.

`tests/cli.rs` covers command-line behaviour and hostile inputs (YAML alias bombs, huge logs).
The charset test in `src/charset.rs` checks the detected charset and confidence for every bundled
translation against `tests/fixtures/charset_golden.tsv`, which was recorded from the C++
uchardet.

The other fixtures are copied unchanged from the upstream repos into `tests/fixtures/`.
`.gitattributes` turns off line-ending conversion because the comparisons are byte-for-byte.

## Fuzzing

Needs a nightly toolchain and `cargo install cargo-fuzz`. In the devenv shell, use `fuzz` in place of
`cargo fuzz`. There are two targets: `analyze` (the whole `analyze` path, checksums included) and
`checksum` (the `eac` and `xld` commands).

```
mkdir -p fuzz/corpus/{analyze,checksum}
for f in $(find tests/fixtures -name '*.log'); do
    h=$(sha1sum < "$f" | cut -c1-40); cp "$f" fuzz/corpus/analyze/$h; cp "$f" fuzz/corpus/checksum/$h
done
cargo fuzz run analyze -- -fork=8 -timeout=2 -rss_limit_mb=1024
```

`-timeout` and `-rss_limit_mb` report slow or memory-hungry inputs as well as crashes. Failing
inputs are saved in `fuzz/artifacts/<target>/`; rerun one with `cargo fuzz run analyze <file>`.

## Layout

| Path | Contents |
|------|----------|
| `src/logchecker.rs` | Port of `Logchecker.php`: the EAC/XLD parser and scoring |
| `src/ripper.rs` | Port of `Check/Ripper.php`: detects which ripper wrote a log |
| `src/whipper.rs` | Whipper (YAML) log parsing |
| `src/checksum/` | EAC (Rijndael-256), XLD and whipper checksum verification |
| `src/charset.rs` | Encoding detection and conversion to UTF-8 |
| `src/uchardet.rs` | Pure-Rust port of uchardet (from cchardet 2.2.0a2) |
| `src/uchardet_data.rs` | uchardet state machines and language models, generated by `scripts/gen_uchardet.py` |
| `src/codepages.rs` | Single-byte code-page tables, generated by `scripts/gen_codepages.py` from glibc iconv |
| `src/translator.rs` | EAC log translation, using `resources/languages/*.json` |
| `resources/` | Upstream's drive offset table and EAC translations, embedded in the binary |
| `src/php.rs` | The PHP semantics the port relies on: loose comparison, `version_compare`, `json_encode`, … |
| `src/console.rs` | Symfony Console's style-tag formatter |
| `src/main.rs` | The command-line interface |
| `src/lib.rs` | The library crate the binary, tests and fuzz targets use |
| `scripts/` | Generators for `src/uchardet_data.rs` and `src/codepages.rs` |
| `tests/` | Ported upstream tests, CLI tests and fixtures |
| `fuzz/` | cargo-fuzz targets |

## Known differences

- `analyze`'s details JSON escapes non-ASCII characters as `\uXXXX`, as PHP's `json_encode`
  does. A few upstream fixture files store those characters literally. The decoded content
  is the same.
- Some rarer multibyte encodings cannot be decoded: EUC-TW, HZ, ISO-2022-CN and ISO-2022-KR.
  PHP's iconv converts them.
- Whipper logs that contain YAML aliases are rejected as unparseable. Whipper never writes
  them, and nested aliases would use unbounded memory.

## Why uchardet is ported

Upstream relies on `cchardet` to detect each log's encoding, and the charset and confidence
it reports decide how the log is decoded. The upstream fixtures were produced with
cchardet 2.2.0a2, and newer detectors (including later cchardet releases) disagree on some
of them. Porting that exact uchardet to Rust is the only way to get identical results.

`src/uchardet_data.rs` holds the tables from that release. To regenerate it, run:

```
python3 scripts/gen_uchardet.py
```

The script downloads the cchardet 2.2.0a2 sdist from PyPI, checks it against a pinned sha256 and
reads the uchardet sources bundled inside. To work offline, pass an unpacked source dir instead:
`python3 scripts/gen_uchardet.py cchardet-2.2.0a2/src/ext/uchardet/src`.

The output should be byte-identical to the committed file. The charset golden test checks the
detection results.

`src/codepages.rs` is regenerated the same way, on a glibc system, from glibc's own iconv:

```
python3 scripts/gen_codepages.py src/codepages.rs
```

## Licence

MIT; see [LICENSE](LICENSE). The EAC and XLD checksum code and their fixtures are derived from
puddly's MIT-licensed eac_logchecker.py and xld_logchecker.py, and their notice is included in
LICENSE. The Logchecker fixtures and `resources/` come from OPSnet/Logchecker, which is public
domain (Unlicense). `src/uchardet.rs` and `src/uchardet_data.rs` are derived from uchardet
(Mozilla universalchardet) under MPL 1.1, GPL 2.0 or LGPL 2.1.
