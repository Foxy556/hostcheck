"""Testes do hostcheck — rodam sem rede para os casos de falha."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import hostcheck as hc  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class TestNormalize(unittest.TestCase):
    def test_host_puro(self):
        raw, host, ports = hc.normalize("github.com", (80, 443))
        self.assertEqual(raw, "github.com")
        self.assertEqual(host, "github.com")
        self.assertEqual(ports, (80, 443))

    def test_url_com_esquema(self):
        _, host, _ = hc.normalize("https://api.exemplo.com", (80, 443))
        self.assertEqual(host, "api.exemplo.com")

    def test_url_com_porta_explicita(self):
        _, host, ports = hc.normalize("http://localhost:3000", (80, 443))
        self.assertEqual(host, "localhost")
        self.assertEqual(ports, (3000,))

    def test_url_http_adiciona_porta_80(self):
        _, _, ports = hc.normalize("http://exemplo.com", (443,))
        self.assertIn(80, ports)

    def test_alvo_invalido(self):
        with self.assertRaises(ValueError):
            hc.normalize("", (80,))


class TestRender(unittest.TestCase):
    def _report(self, status=hc.OK):
        r = hc.Report(target="exemplo.com", host="exemplo.com")
        r.checks.append(hc.Check("dns", status, "1.2.3.4", 5.0))
        return r

    def test_texto_contem_alvo_e_status(self):
        out = hc.render_text([self._report()])
        self.assertIn("exemplo.com", out)
        self.assertIn(hc.OK, out)

    def test_json_e_valido_e_traz_status(self):
        data = json.loads(hc.render_json([self._report(hc.FAIL)]))
        self.assertEqual(data["results"][0]["status"], hc.FAIL)
        self.assertEqual(data["results"][0]["target"], "exemplo.com")
        self.assertIn("generated_at", data)

    def test_markdown_e_tabela(self):
        out = hc.render_markdown([self._report()])
        self.assertTrue(out.startswith("| Alvo |"))
        self.assertIn("**OK**", out)


class TestFalhaReal(unittest.TestCase):
    """Host que não resolve deve sair com FAIL e código de saída 1."""

    def test_host_inexistente(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "hostcheck.py"),
             "nao-existe-neste-dominio.invalid", "--timeout", "2", "--no-color"],
            capture_output=True, text=True, cwd=ROOT, timeout=60,
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("FAIL", proc.stdout)

    def test_saida_json_no_cli(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "hostcheck.py"),
             "nao-existe-neste-dominio.invalid", "--timeout", "2", "--json"],
            capture_output=True, text=True, cwd=ROOT, timeout=60,
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["results"][0]["status"], "FAIL")


class TestArgumentos(unittest.TestCase):
    def test_ports_invalido_retorna_2(self):
        self.assertEqual(hc.main(["x.com", "--ports", "abc"]), 2)

    def test_portas_vazias_retornam_2(self):
        self.assertEqual(hc.main(["x.com", "--ports", ","]), 2)


if __name__ == "__main__":
    unittest.main()
