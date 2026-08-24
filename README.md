# PHP Shell Injection Companion

Warning on `eval(`, `exec(`, `shell_exec(`, `system(`, `passthru(`, or
`popen(` whose argument is a double-quoted string with `$variable`
interpolation, or a concatenation with a variable, rather than a
static literal. PHP's own official manual states this for `eval()`:
"pay special attention not to pass any user provided data into it
without properly validating it beforehand" — the same class of risk
applies to the shell-executing functions, all of which run their
string argument through a real system shell.

Confirmed real gap: "PHP Inspections (EA Extended)" (one of the most
widely used PHP inspection plugins on Marketplace) covers
`unserialize()`, weak crypto, SSL bypass, and several other security
patterns, but not `eval()`/`exec()`/`shell_exec()`/`system()` with
dynamic arguments — confirmed by reading its own documented security
feature list before building this.

## Why it exists

```php
exec("ping -c 1 $host");
```

compiles and runs fine — until `$host` ever contains something like
`"; rm -rf /"` from user input, at which point it's a full shell
command injection.

## Why built this way

- **100% static text analysis** — a regex-based line scanner, not a
  real PHP parser, so it works whether the PHP plugin is installed or
  not.

## v0.1 scope — stated honestly, not exhaustively

Doesn't trace whether the interpolated value actually originates from
untrusted input, so interpolation of a hardcoded constant is a
possible (rare) false positive. A call whose argument is entirely a
static literal is correctly never flagged.

## Usage

Open any `.php` file. An `eval`/`exec`/`shell_exec`/`system`/
`passthru`/`popen` call with an interpolated/concatenated string
argument shows a warning.

## Enterprise / Team Licensing

Need enterprise features, custom rules, or team licensing? Contact us at
**gaphunterlabs@gmail.com**.

## Development

```
./gradlew test           # unit tests
./gradlew buildPlugin    # generates build/distributions/*.zip
./gradlew verifyPlugin   # checks compatibility against real IDEs
```

## License

Apache-2.0. See `LICENSE`.
