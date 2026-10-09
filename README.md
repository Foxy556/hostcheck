<div align="center">

# 🔎 hostcheck

**Verificação rápida de conectividade: DNS, portas, HTTP e certificado TLS — em uma saída legível.**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 🇧🇷 Por que

Quando algo cai, as primeiras perguntas são sempre as mesmas: *o DNS resolve? a porta abre?
o site responde? o certificado está válido?*

O `hostcheck` responde as quatro de uma vez, para vários alvos, em paralelo — e sai com
código `1` quando algo falha, então dá para usar direto em cron, CI ou alerta.

Só biblioteca padrão do Python: **nada para instalar**.

---

## 🚀 Uso

```bash
python hostcheck.py github.com
python hostcheck.py https://github.com --ports 443
python hostcheck.py api.exemplo.com --ports 80,443,8080 --timeout 3
python hostcheck.py github.com 1.1.1.1 --json
python hostcheck.py site.com --markdown > status.md
```

### Saída padrão

```
[OK] github.com
    OK   dns         5.0 ms  140.82.112.3, 140.82.113.3, 140.82.114.3
    OK   tcp/80      8.1 ms  conectado
    OK   tcp/443     7.9 ms  conectado
    OK   http       152.4 ms  HTTP 200
    OK   tls        180.2 ms  válido por mais 89 dia(s)
```

### Opções

| Opção | Descrição | Padrão |
|---|---|---|
| `--ports` | portas TCP separadas por vírgula | `80,443` |
| `--timeout` | timeout por verificação, em segundos | `5.0` |
| `--json` | saída estruturada | — |
| `--markdown` | tabela Markdown (pronta para README) | — |
| `--no-color` | desativa cores ANSI | — |

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | tudo OK (ou só avisos) |
| `1` | alguma verificação falhou |
| `2` | erro de uso (alvo ou porta inválida) |

---

## 🧠 O que é verificado

1. **DNS** — `getaddrinfo`, com os endereços resolvidos e o tempo
2. **TCP** — conexão real por porta, com latência
3. **HTTP** — status da resposta; `4xx/5xx` vira `WARN`/`FAIL`
4. **TLS** — validade do certificado; alerta com menos de 14 dias, falha se expirado

---

## 🧪 Testes

```bash
python -m unittest discover -s tests -v
```

Os casos de falha usam um domínio `.invalid` (garantido por RFC 2606 para não resolver),
então os testes **não dependem de rede** para o caminho de erro.

---

## 📄 Licença

Distribuído sob a licença [MIT](LICENSE).

---

<div align="center">

**Veja também:** [net_troubleshoot](https://github.com/Foxy556/net_troubleshoot) ·
[status-page](https://github.com/Foxy556/status-page) ·
[Perfil](https://github.com/Foxy556)

</div>
