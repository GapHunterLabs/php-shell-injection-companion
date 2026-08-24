package dev.gaphunter.phpshellinjectioncompanion.detect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ShellInjectionScannerTest {

    @Test
    fun `flags exec with double-quoted interpolated argument`() {
        val code = """exec("ping -c 1 ${'$'}host");"""
        val hits = ShellInjectionScanner.scan(code)
        assertEquals(1, hits.size)
        assertEquals("exec", hits[0].callText)
    }

    @Test
    fun `flags shell_exec with double-quoted interpolated argument`() {
        val code = """shell_exec("convert ${'$'}filename out.png");"""
        val hits = ShellInjectionScanner.scan(code)
        assertEquals(1, hits.size)
        assertEquals("shell_exec", hits[0].callText)
    }

    @Test
    fun `flags system with concatenated argument`() {
        val code = """system('ping ' . ${'$'}host);"""
        val hits = ShellInjectionScanner.scan(code)
        assertEquals(1, hits.size)
        assertEquals("system", hits[0].callText)
    }

    @Test
    fun `does not flag single-quoted literal argument with a dollar sign`() {
        val code = """exec('echo ${'$'}5.00');"""
        assertTrue(ShellInjectionScanner.scan(code).isEmpty())
    }

    @Test
    fun `does not flag a plain literal string argument`() {
        val code = """system("uptime");"""
        assertTrue(ShellInjectionScanner.scan(code).isEmpty())
    }

    @Test
    fun `does not flag a commented-out line`() {
        val code = """// exec("ping ${'$'}host");"""
        assertTrue(ShellInjectionScanner.scan(code).isEmpty())
    }
}
