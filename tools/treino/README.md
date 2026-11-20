# Treino do classificador de IA

Pipeline que gera o modelo do classificador local (`mandacaru.ml`). Roda **só** no ambiente isolado
(`UbuntuPentest` endurecida, dentro de `bubblewrap` sem rede); nunca na máquina de desenvolvimento. Passo a passo
completo: Parte B do plano `docs/superpowers/plans/2026-11-20-classificador-ia-treino.md`.

## Regras de ouro

1. **Nenhuma amostra é executada.** O código daqui não importa `subprocess`, `pty`, `ctypes`, `importlib`, `pickle`…
   e não chama `os.system`, `os.exec*`, `posix_spawn`, `eval`. O teste `tests/treino/test_politica_treino.py` barra
   isso no CI.
2. **Nenhuma amostra sai do zip.** O zip AES (senha `infected`) é lido direto na memória, com limite de 8 MB; nada de
   `extract`, `extractall` ou `unpack_archive`.
3. **Nenhuma ferramenta externa toca nas amostras** (`file`, `readelf`, `objdump`, `strings`, `ldd`…).
4. **Corpus fora de qualquer repositório git**, fora das pastas vigiadas e fora de `/mnt`.
5. **Saem do ambiente só números e texto validado:** `elf.json`, `script.json`, `golden.json`, relatório e
   manifesto de hashes.

## CPU, nunca GPU

O treino usa `HistGradientBoostingClassifier` do scikit-learn: **100 % CPU, 0 % GPU**. Nada de CUDA; o sandbox não
monta `/dev/dxg`, então a placa de vídeo nem é visível. Rode com `OMP_NUM_THREADS=4 nice -n 15` para não pesar no
computador.

## Dependências

`pip install --require-hashes -r tools/treino/requirements.txt` num venv próprio. O `yara-python` (usado pelo
`StaticScanner` para marcar o que as regras atuais já pegam) não tem wheel para o Python 3.14: use o pacote do
sistema, `sudo apt install python3-yara`, e crie o venv com `python3 -m venv --system-site-packages`.
