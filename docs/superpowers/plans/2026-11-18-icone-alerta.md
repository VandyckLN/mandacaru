# Ícone do Mandacaru no popup de alerta — plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** o popup de alerta do vigia da distro mostra o mandacaru pixel art de óculos browline, distribuído pela .deb do Mandacaru 0.3.1.

**Architecture:** o Mandacaru instala um PNG 64×64 indexado em `/usr/share/icons/hicolor/64x64/apps/mandacaru.png`; a distro fixa a 0.3.1 no lock e passa `--icon=mandacaru` ao `notify-send`. O mako resolve o nome pelo tema hicolor. Dois repositórios, nesta ordem: `~/projetos/mandacaru` (Tasks 1–3), depois `~/projetos/Distro` (Tasks 4–6).

**Tech Stack:** debhelper (`dh_install`), pytest, GitHub Actions (`deb.yml`, `release.yml`), Bash E2E da distro (`tests/e2e`), `notify-send`/mako.

**Spec:** `docs/superpowers/specs/2026-11-18-icone-alerta-design.md` (no repo mandacaru)

## Global Constraints

- Ícone: PNG 64×64, paleta indexada (color type 3) com transparência (`tRNS`), ≤ 1024 bytes; é a grade 32×32 do spec ampliada 2× por vizinho mais próximo.
- Caminho instalado: `usr/share/icons/hicolor/64x64/apps/mandacaru.png`. Fonte no repo: `packaging/icons/64x64/mandacaru.png`.
- Versão nova: `0.3.1`. Tag `v0.3.1`. Asset `mandacaru_0.3.1_all.deb`.
- Nenhuma dependência nova em nenhum dos dois pacotes. O `Depends: mandacaru (>= 0.3.0)` do `lumen-desktop` fica como está: sem ícone o popup funciona igual (call do plano).
- Flag na distro: `--icon=mandacaru`, logo depois de `--app-name=Mandacaru`.
- Branch por repo antes de commitar; nada direto no `main`. Commits terminam com `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Mandacaru 0.3.0 ainda instalado (ícone ausente):** o popup aparece normal, sem ícone e sem erro. Coberto pelo design do mako; o harness da Task 5 não depende do arquivo existir.
2. **PNG regenerado errado (RGB, 32×32 ou >1 KB):** o mako amplia e borra, ou pesa mais. Fixado pelo teste da Task 1.
3. **Arquivo fora do `mandacaru.install`:** a .deb sai sem ícone e ninguém percebe. Fixado pelo `deb.yml` da Task 1.
4. **SHA256 do lock com a .deb errada:** o build da ISO aborta. Fixado pelo tier 1 da Task 4.
5. **Comando do `notify-send` muda em outros asserts do tier 2:** todos os asserts com a linha inteira precisam do `--icon` novo (Task 5).

---

### Task 1: Ícone no pacote (mandacaru)

**Files:**
- Create: `packaging/icons/64x64/mandacaru.png`
- Modify: `debian/mandacaru.install`, `.github/workflows/deb.yml:27` (lista do `for f in ...`)
- Test: `tests/test_packaging.py`

**Interfaces:** Produces: `usr/share/icons/hicolor/64x64/apps/mandacaru.png` na .deb (Task 3 e a distro dependem desse caminho).

- [ ] **Step 1:** `git switch -c feat/icone-alerta`.
- [ ] **Step 2: Escrever os testes que falham** em `tests/test_packaging.py`:

```python
def test_icone_e_png_64_indexado_e_leve():
    png = (ROOT / "packaging" / "icons" / "64x64" / "mandacaru.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    largura, altura, _, tipo_cor = struct.unpack(">IIBB", png[16:26])
    assert (largura, altura, tipo_cor) == (64, 64, 3)   # paleta: 1:1 no max-icon-size do mako
    assert b"tRNS" in png                                # fundo transparente
    assert len(png) <= 1024


def test_icone_vai_para_o_hicolor():
    install = (ROOT / "debian" / "mandacaru.install").read_text()
    assert "packaging/icons/64x64/mandacaru.png usr/share/icons/hicolor/64x64/apps/" in install
```

(`import struct` no topo.)

- [ ] **Step 3:** `.venv/bin/python -m pytest -q tests/test_packaging.py` → os 2 novos FALHAM (arquivo ausente).
- [ ] **Step 4:** copiar `/tmp/mandacaru-icones/mandacaru-final-64.png` para `packaging/icons/64x64/mandacaru.png`. Se o `/tmp` tiver sido limpo, gerar de novo a partir da grade e da paleta do spec (cada célula vira 2×2 pixels, `.` = índice 0 transparente, filtro 0, só stdlib `zlib`/`struct`), sem versionar o script.
- [ ] **Step 5:** adicionar a linha `packaging/icons/64x64/mandacaru.png usr/share/icons/hicolor/64x64/apps/` em `debian/mandacaru.install`; adicionar `usr/share/icons/hicolor/64x64/apps/mandacaru.png` na lista `for f in ...` do passo "Confere o conteudo do pacote" do `deb.yml`.
- [ ] **Step 6:** `.venv/bin/python -m pytest -q` → tudo PASSA.
- [ ] **Step 7:** commit `Icone do Mandacaru no hicolor 64x64 para o popup de alerta` (inclui o spec e este plano).

### Task 2: Versão 0.3.1 (mandacaru)

**Files:** Modify: `src/mandacaru/__init__.py:8`, `debian/changelog` (entrada nova no topo), `CHANGELOG.md` (seção `## 0.3.1` acima da 0.3.0).

**Interfaces:** Consumes: Task 1. Produces: versão `0.3.1` coerente (os testes `test_versao_do_changelog_debian_bate_com_o_pacote` e `test_nome_no_pypi_e_changelog_da_versao` já existem).

- [ ] **Step 1:** trocar `__version__` para `"0.3.1"` → `pytest -q tests/test_packaging.py` FALHA nos dois testes de versão.
- [ ] **Step 2:** `debian/changelog`: entrada `mandacaru (0.3.1) unstable; urgency=medium` com `* Icone do Mandacaru em /usr/share/icons/hicolor/64x64/apps/mandacaru.png.`, mesmo formato de assinatura/data RFC 2822 da 0.3.0. `CHANGELOG.md`: `## 0.3.1` + uma linha dizendo que o pacote traz o ícone (PNG 64×64, 382 bytes) para popups de alerta, nome `mandacaru` no tema hicolor.
- [ ] **Step 3:** `.venv/bin/python -m pytest -q` → PASSA.
- [ ] **Step 4:** commit `Versao 0.3.1: icone do Mandacaru`.

### Task 3: PR, release e conferência (mandacaru)

**Interfaces:** Produces: `https://github.com/VandyckLN/mandacaru/releases/download/v0.3.1/mandacaru_0.3.1_all.deb` e o SHA256 dela (Task 4).

- [ ] **Step 1:** `git push -u origin feat/icone-alerta` e `gh pr create` (corpo termina com `🤖 Generated with [Claude Code](https://claude.com/claude-code)`). Esperar o CI verde (`gh pr checks --watch`), incluindo o `deb` com o ícone na lista de conteúdo.
- [ ] **Step 2:** merge do PR, depois `git switch main && git pull`, `git tag v0.3.1 && git push origin v0.3.1`. Esperar o `release.yml` (`gh run watch`).
- [ ] **Step 3:** baixar o asset num diretório novo e vazio; `dpkg-deb -c` mostra `./usr/share/icons/hicolor/64x64/apps/mandacaru.png`; `sha256sum` anotado para a Task 4.

### Task 4: Lock da distro na 0.3.1 (Distro)

**Files:** Modify: `packaging/third-party/mandacaru.lock`, `tests/e2e/tier1_feature_coverage.sh:572-575` (T1_F9_01).

- [ ] **Step 1:** `git switch -c feat/icone-mandacaru` no `~/projetos/Distro`.
- [ ] **Step 2:** no T1_F9_01, trocar `0\.3\.0` → `0\.3\.1` na versão e na URL (`v0\.3\.1/mandacaru_0\.3\.1_all\.deb`), e o SHA256 fixo pelo da Task 3; os textos das mensagens também dizem 0.3.1.
- [ ] **Step 3:** `bash tests/e2e/run-e2e-tests.sh --tier 1` → T1_F9_01 FALHA.
- [ ] **Step 4:** atualizar as três chaves do `mandacaru.lock` (versão `0.3.1`, URL da Task 3, SHA256 da Task 3).
- [ ] **Step 5:** `bash tests/e2e/run-e2e-tests.sh --tier 1` → PASSA; `bash packaging/fetch-third-party.sh` baixa e confere o SHA sem erro.
- [ ] **Step 6:** commit `Mandacaru 0.3.1 no lock (icone do popup)`.

### Task 5: `--icon=mandacaru` no popup (Distro)

**Files:** Modify: `shell/edr_notify.py:128` (`notify`), `tests/e2e/tier2_boundary_corner.sh` (asserts F9 que trazem a linha do `notify-send`, ex. 774 e 782).

**Interfaces:** Consumes: nome de ícone `mandacaru` (Task 1).

- [ ] **Step 1:** nos asserts do tier 2 que casam a linha do `notify-send`, inserir ` --icon=mandacaru` logo depois de `--app-name=Mandacaru` (ex.: `notify-send --app-name=Mandacaru --icon=mandacaru --urgency=critical --wait ...`). `grep -n "notify-send --app-name" tests/e2e/tier2_boundary_corner.sh` lista todos.
- [ ] **Step 2:** `bash tests/e2e/run-e2e-tests.sh --tier 2` → esses asserts FALHAM.
- [ ] **Step 3:** em `notify()`, a lista passa a começar `["notify-send", "--app-name=Mandacaru", "--icon=mandacaru", *opts, ...]`.
- [ ] **Step 4:** `bash tests/e2e/run-e2e-tests.sh --tier 2` → PASSA; `--tier all` → sem regressão.
- [ ] **Step 5:** commit `Popup do Mandacaru com o icone do mandacaru`.

### Task 6: ISO, VM e PR (Distro)

- [ ] **Step 1:** `sudo UBUNTU_MIRROR=https://archive.ubuntu.com/ubuntu ./scripts/build-iso.sh --clean </dev/null 2>&1 | tee dist/build-iso.log` (pedir ao usuário rodar com `!` se o sudo pedir senha). Build termina sem erro.
- [ ] **Step 2:** na VM (live): `ls /usr/share/icons/hicolor/64x64/apps/mandacaru.png` existe; disparar o EICAR (`printf ... > ~/Downloads/eicar.txt`) e o usuário confirma o popup com o mandacaru nítido.
- [ ] **Step 3:** push do branch e `gh pr create` na distro (mesmo rodapé do PR).
