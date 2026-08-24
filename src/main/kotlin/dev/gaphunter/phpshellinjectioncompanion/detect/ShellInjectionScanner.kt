package dev.gaphunter.phpshellinjectioncompanion.detect

import dev.gaphunter.phpshellinjectioncompanion.model.ShellInjectionHit

/**
 * Plain-text line scanner for a PHP file -- flags `eval(`, `exec(`,
 * `shell_exec(`, `system(`, `passthru(`, or `popen(` whose argument
 * is a double-quoted string containing `$variable` interpolation, or
 * a concatenation (`.`) with a variable, rather than a static
 * literal. PHP's own official manual states this plainly for
 * `eval()`: "pay special attention not to pass any user provided
 * data into it without properly validating it beforehand" -- the
 * same class of risk applies to the shell-executing functions
 * (`exec`/`shell_exec`/`system`/`passthru`/`popen`), all of which run
 * their string argument through a real system shell.
 *
 * Confirmed real gap: "PHP Inspections (EA Extended)" (one of the
 * most widely used PHP inspection plugins on Marketplace) covers
 * `unserialize()`, weak crypto, SSL bypass, and several other
 * security patterns, but not `eval()`/`exec()`/`shell_exec()`/
 * `system()` with dynamic arguments -- confirmed by reading its own
 * documented security feature list before building this.
 *
 * **v0.1 scope, stated honestly:** plain-text regex matching, not
 * real PHP PSI -- doesn't trace whether the interpolated value
 * actually originates from untrusted input, so interpolation of a
 * hardcoded constant is a possible (rare) false positive. A call
 * whose argument is entirely a static literal (no `$` interpolation,
 * no `.` concatenation) is correctly never flagged.
 */
object ShellInjectionScanner {

    // Only double-quoted strings interpolate $variables in PHP -- a single-quoted 'echo $x;' is a literal
    // string with no interpolation, so the interpolation check is deliberately scoped to `"` only.
    private val DANGEROUS_CALL = Regex(
        """\b(eval|exec|shell_exec|system|passthru|popen)\s*\(\s*"(?:[^"\\]|\\.)*\$\w""",
    )
    private val CONCAT_CALL = Regex(
        """\b(eval|exec|shell_exec|system|passthru|popen)\s*\(\s*(["'])(?:[^"'\\]|\\.)*\2\s*\.\s*\$\w""",
    )

    fun scan(text: String): List<ShellInjectionHit> {
        val hits = mutableListOf<ShellInjectionHit>()
        text.lines().forEachIndexed { index, rawLine ->
            val trimmed = rawLine.trimStart()
            if (trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("*")) return@forEachIndexed

            val match = DANGEROUS_CALL.find(rawLine) ?: CONCAT_CALL.find(rawLine) ?: return@forEachIndexed
            hits += ShellInjectionHit(match.groupValues[1], index + 1, match.range.first, match.range.last + 1)
        }
        return hits
    }
}
