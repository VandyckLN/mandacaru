# Como contribuir

Contribuições são bem-vindas: regras novas, correção de falso positivo, coletores, documentação.

## Ambiente

```bash
git clone https://github.com/VandyckLN/mandacaru && cd mandacaru
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Se o `pip` tentar compilar o `yara-python` e falhar com `Python.h: No such file or directory`, instale os headers: `sudo apt install python3-dev libssl-dev`.

## Antes de abrir um pull request

```bash
ruff check .
pytest -q
```

Os dois rodam no CI em Python 3.10 a 3.14 e precisam passar.

## Montando o `.deb` localmente

```bash
sudo apt install build-essential debhelper dh-python pybuild-plugin-pyproject python3-all python3-setuptools \
  python3-pytest python3-yara python3-psutil python3-watchdog
dpkg-buildpackage -us -uc -b      # gera ../mandacaru_<versão>_all.deb
```

O CI faz o mesmo, instala o pacote e confere que o serviço detecta um arquivo de teste.

## Lançando uma versão

Atualize `__version__` em `src/mandacaru/__init__.py`, o topo de `debian/changelog` e o `CHANGELOG.md` (um teste confere que os três batem). Depois do merge, `git tag vX.Y.Z && git push origin vX.Y.Z` dispara a publicação.

## Regras do projeto

- **Nada de malware real no repositório.** Os testes usam amostras inofensivas que imitam a *técnica* (por exemplo, base64 de um `print`), nunca um payload funcional.
- **Toda detecção nova vem com dois testes:** um que dispara e um arquivo legítimo parecido que não dispara.
- **Detecte a técnica, não os bytes.** Hash e string exata envelhecem rápido; prefira o que o código precisa *fazer*.
- **Falso positivo é bug.** Ao relatar, mande o nome da regra, o caminho do arquivo e, se puder, o arquivo.
- Regras YARA levam `description` e `severity` no `meta`, e `mitre` quando houver técnica correspondente.

## Licença

Ao contribuir, você concorda em licenciar seu código sob GPL-3.0-or-later.
