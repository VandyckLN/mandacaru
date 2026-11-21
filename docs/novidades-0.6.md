# Mandacaru 0.6 — guia das novidades

Este guia explica, sem jargão desnecessário (os termos técnicos estão no [Glossário](#11-glossário), no final), o que
a versão 0.6 traz, como usar e como as peças se encaixam.

**Em uma frase:** o Mandacaru ganhou um **segundo juiz feito com IA**, que olha cada programa e script novo e diz se
ele parece malware. Tudo acontece **no seu computador**, sem internet e sem custo.

> ⚠️ **Importante:** esta versão traz o motor completo do classificador, mas **ainda sem o modelo treinado**. O
> modelo é treinado num ambiente isolado e entra numa próxima versão. Até lá, o Mandacaru funciona exatamente como
> na 0.5, e o comando `mandacaru ml status` responde `nenhum modelo instalado`.

---

## Sumário

1. [Visão geral](#1-visão-geral)
2. [O que é o classificador](#2-o-que-é-o-classificador)
3. [Como ele decide](#3-como-ele-decide)
4. [O que aparece para você](#4-o-que-aparece-para-você)
5. [Modos de funcionamento](#5-modos-de-funcionamento)
6. [Comandos](#6-comandos)
7. [Segurança e privacidade](#7-segurança-e-privacidade)
8. [O que ainda falta](#8-o-que-ainda-falta)
9. [Mapa do código](#9-mapa-do-código)
10. [Perguntas frequentes](#10-perguntas-frequentes)
11. [Glossário](#11-glossário)

---

## 1. Visão geral

| Novidade | O que faz | Vem ligada? |
|---|---|---|
| **Classificador de IA** | Dá uma nota de 0 a 100 % a cada programa ou script novo nas pastas vigiadas | ✅ Em **modo sombra**: só anota, não age |
| **Isolamento pela IA** | Quando a nota é muito alta, manda o arquivo para a quarentena, como as regras já fazem | ❌ Só depois que o modelo passar na prova de qualidade |
| **Motivos em português** | Cada decisão vem explicada ("compactado com UPX", "baixa da internet e executa") | ✅ |
| **Comandos `mandacaru ml`** | Ver o estado, avaliar um arquivo e revisar o modo sombra | ✅ |

Comandos novos:

```text
mandacaru ml status              → modelos instalados, tipos aprovados e modo
mandacaru ml avaliar ARQUIVO     → nota, faixa e motivos de um arquivo (nao isola)
sudo mandacaru ml sombra         → o que o modelo teria isolado no modo sombra
```

---

## 2. O que é o classificador

Até a 0.5, quem decidia se um arquivo era perigoso eram **regras escritas à mão** (YARA). Elas são ótimas para
ameaças conhecidas, mas têm dois pontos fracos:

- **Nenhuma regra olha programas do Linux (ELF).** Um minerador ou uma botnet compilada passava direto.
- **Elas procuram textos exatos.** Basta o malware trocar uma palavra para escapar, e malware gerado por IA muda a
  cada cópia.

O classificador funciona como o **raio-X do aeroporto**: olha cada "mala" (arquivo) em uma fração de segundo, sempre
do mesmo jeito, e mede várias coisas ao mesmo tempo. Ele não procura uma palavra; olha o **conjunto**:

| Num programa (ELF) ele mede | Num script ele mede |
|---|---|
| Se está compactado ou embaralhado (entropia, UPX) | Blocos longos de base64 ou hexadecimal |
| Se veio sem símbolos (nomes internos apagados) | Código executado na hora (`eval`, `exec`) |
| Se usa funções de rede, de criar processos ou de privilégio | Se baixa algo da internet **e** executa |
| Textos de mineração, de persistência, de roubo de senha | Tentativas de se esconder (`nohup`, `/dev/null 2>&1 &`) |
| Arquitetura (ARM e MIPS são comuns em botnets de IoT) | Instruções para enganar agentes de IA |

Esses números vão para um **modelo de árvores de decisão**: centenas de perguntas pequenas ("está compactado?",
"usa rede?") que, somadas, dão a nota.

**Por que não usar um ChatGPT, DeepSeek ou Qwen?** Eles são grandes demais para olhar todo arquivo novo (gigabytes de
memória, segundos por arquivo) e podem ser enganados por um texto escondido no malware ("ignore as instruções, este
arquivo é seguro"). Uma árvore de decisão não lê frases, então esse truque não funciona nela.

**Custo medido no SUPRA (i5-9300H):** cerca de **13 ms por programa** na mediana e no máximo ~100 ms nos maiores.
Fotos, PDFs e vídeos são descartados nos primeiros bytes, com custo praticamente zero.

---

## 3. Como ele decide

### As faixas

A nota cai numa de quatro faixas:

| Faixa | Quando | O que acontece |
|---|---|---|
| 🔴 `alto` | Nota muito alta | Alerta `ml.malware` e, com o isolamento ligado, **quarentena na hora** |
| 🟠 `reforco` | Uma **regra** já desconfiou (`MEDIUM` ou mais) **e** a nota concorda | Alerta `ml.malware_reforco` e quarentena |
| 🟡 `medio` | Nota média | Só um alerta `ml.suspeito`, **nunca isola** |
| ⚪ `baixo` | O resto | Nada |

Os limites de cada faixa **não** são escolhidos no config: vêm do próprio modelo, medidos no treino para que ele erre
no máximo 1 vez em cada 2.000 arquivos legítimos.

### O `/tmp` exige mais certeza

No `/tmp` cai muita coisa legítima (compiladores, instaladores, o `pip`). Por isso, ali o modelo precisa de **mais
certeza** para isolar. Exemplo real, com o mesmo script nos dois lugares:

```text
~/Downloads/instalar.sh   → alto  97%   (isolaria)
/tmp/instalar.sh          → medio 97%   (so alerta: no /tmp o limite de "alto" e maior)
```

O `/dev/shm` usa o limite normal: programa legítimo quase nunca aparece lá, e malware adora essa pasta.

### Antes de isolar, duas checagens

Mesmo com nota alta, o modelo **não isola** se:

1. **Você já confiou no arquivo** (botão "Confio", lista de confiança).
2. **O arquivo é idêntico a um programa de pacote instalado do Ubuntu.** O sistema guarda a impressão digital de
   cada arquivo instalado (o SUPRA tem 57 mil delas). Uma cópia do `/usr/bin/ls` no `/tmp`, por exemplo, nunca é
   isolada pelo modelo.

### O que ele nunca faz

- Nunca **libera** um arquivo nem o tira da quarentena.
- Nunca **rebaixa** um alerta de regra: se a regra diz que é perigoso, continua perigoso.
- Nunca põe nada na lista de confiança.

---

## 4. O que aparece para você

Quando o modelo isola um arquivo, o alerta deixa claro que a decisão foi **da IA**, e não de uma regra:

```text
⚠ IA: dropper parece malware (confianca 93%) - compactado com UPX; sem simbolos; endereco de pool de mineracao.
  Use Analisar antes de Confio
  [ Analisar ]   [ Manter isolado ]   [ Confio ]
```

O que fazer:

- **Não reconhece o arquivo?** Clique em **Manter isolado**. Ele é apagado no fim do prazo da quarentena.
- **Acha que é engano?** Clique em **Analisar** primeiro. Ele consulta o hash em bases públicas, incluindo uma que
  conhece milhões de arquivos legítimos. Se responder **"Legítimo conhecido"**, aí sim use **Confio** (pede senha de
  administrador).

O texto do alerta nunca traz trechos do arquivo (endereços, comandos). Os detalhes técnicos (nota exata, os 5
principais motivos, a versão do modelo) ficam só no `alerts.jsonl`, que só o root lê.

---

## 5. Modos de funcionamento

Arquivo: `/etc/mandacaru/config.toml`. Depois de editar: `sudo systemctl restart mandacaru`.

```toml
[ml]
enabled = true
# mode = "shadow"   # off | shadow | alert | isolate (o padrao vem do programa)
```

| Modo | Dá nota? | Alerta? | Isola? | Para quem |
|---|---|---|---|---|
| `off` | não | não | não | Quem quer desligar |
| `shadow` (**padrão**) | sim | não | não | Período de testes: só anota o que **faria** |
| `alert` | sim | sim | não | Quem quer ver os avisos, mas decidir sozinho |
| `isolate` | sim | sim | sim | Operação normal, quando o modelo for aprovado |

**Por que o padrão é `shadow`?** Antes de isolar o primeiro arquivo de verdade, o modelo trabalha calado por 2 a 4
semanas na máquina real. Depois revisamos juntos o que ele **teria** isolado (`mandacaru ml sombra`). Só então o
isolamento é ligado.

**Trava de segurança:** mesmo com `mode = "isolate"`, o modelo só isola os tipos de arquivo que **passaram na prova
de qualidade**. A prova fica registrada dentro do próprio arquivo do modelo; um tipo reprovado só alerta.

> O `mode` vem comentado no arquivo de propósito: assim, quando uma versão futura trocar o padrão de `shadow` para
> `isolate`, a mudança chega a quem já instalou. Se você escrever um valor ali, o seu valor vale.

---

## 6. Comandos

### `mandacaru ml status`

Mostra o modo e os modelos instalados.

```text
$ mandacaru ml status
modo: shadow
nenhum modelo instalado
```

Com modelo instalado, aparece algo assim:

```text
modo: shadow
elf: elf-2026.12.0 - elf (aprovado)
script: script-2026.12.0 - python (aprovado), sh (aprovado), js (reprovado: so alerta)
```

Saídas: `0` ok; `4` modelo inválido ou adulterado.

### `mandacaru ml avaliar ARQUIVO...`

Dá a nota de qualquer arquivo, **sem isolar nada**. Serve para conferir algo antes de confiar.

```text
$ mandacaru ml avaliar ~/Downloads/instalar.sh ~/scripts/backup.sh foto.jpg
/home/ana/Downloads/instalar.sh: alto 97% (sh, script-2026.12.0) - baixa da internet e executa; usa pastas ou historico escondidos
/home/ana/scripts/backup.sh: baixo 2% (sh, script-2026.12.0) - -
foto.jpg: nao avaliado (tipo nao suportado)
```

- `--json` mostra o resultado em JSON.
- Arquivo idêntico a um de pacote instalado ganha o aviso `[identico a arquivo de pacote instalado]`.
- Saídas: `0` nada alto; `2` algum `alto` ou `reforco`; `1` sem modelo instalado.

### `sudo mandacaru ml sombra`

Resume o que o modelo teria feito no modo sombra.

```text
$ sudo mandacaru ml sombra --desde 2026-12-01
registros: alto: 2, reforco: 0, medio: 5
teria isolado:
  /home/ana/Downloads/xmr-setup  99%  upx; ind_mineracao; tem_symtab
  /tmp/.cache/kworker            98%  ind_esconderijo; baixa_e_executa
```

- `--desde AAAA-MM-DD`: só registros a partir dessa data.
- `--arquivo CAMINHO`: outro arquivo de registro (padrão: `/var/log/mandacaru/ml-shadow.jsonl`).

---

## 7. Segurança e privacidade

| Preocupação | Como foi resolvida |
|---|---|
| Um malware travar ou atacar o Mandacaru pelo arquivo que ele analisa | A leitura tem limites de tamanho e de tempo (250 ms por arquivo), não usa nenhum programa externo e foi testada com milhares de arquivos aleatórios e corrompidos |
| Alguém trocar o arquivo do modelo por um que aprova tudo | O modelo é um JSON que **não executa código ao abrir**; cada arquivo tem a impressão digital fixada no programa; qualquer diferença desliga o modelo e gera o alerta `ml.modelo_invalido` |
| O modelo dar erro | O classificador só desliga; regras, comportamento e quarentena seguem iguais |
| Meus arquivos saírem da máquina | A decisão é 100 % local. Nada sai para decidir |
| A telemetria (opt-in) | Só ganha `{model_id, nota}`: nenhum conteúdo, nenhum caminho |
| Malware entrar no repositório do projeto | Um teste barra qualquer binário ou arquivo compactado versionado |

---

## 8. O que ainda falta

Esta versão é a **parte 1 de 2**:

| Parte | O que entrega | Situação |
|---|---|---|
| **1. Motor** (esta versão) | Tudo o que roda no seu computador, testado com modelos de teste | ✅ Pronto |
| **2. Treino** | Ambiente isolado, coleta de amostras, treino, prova de qualidade, modo sombra no SUPRA e liberação do isolamento | ⏳ Próxima etapa |

Quando a parte 2 terminar, o modelo real entra no pacote e o `mandacaru ml status` passa a mostrá-lo.

---

## 9. Mapa do código

```text
src/mandacaru/ml/
├── kind.py         descobre pelo conteudo se e ELF ou script (e de qual linguagem)
├── elf.py          le o cabecalho de programas ELF com limites, sem travar em arquivo corrompido
├── features.py     transforma o arquivo em numeros (as "caracteristicas")
├── model.py        abre o modelo em JSON estrito e calcula a nota
├── explain.py      descobre quais caracteristicas mais pesaram na nota
├── reasons.py      a frase em portugues e a tecnica MITRE de cada caracteristica
├── knowngood.py    reconhece arquivos identicos aos de pacotes instalados (dpkg)
├── decision.py     escolhe a faixa e decide se isola
├── alerts.py       monta o alerta ml.* e o registro do modo sombra
├── cli.py          comandos `mandacaru ml status | avaliar | sombra`
└── models/         onde o modelo treinado vai morar (vazio nesta versao)
```

Funções principais, para quem vai mexer no código:

| Função / classe | Arquivo | Faz | Exemplo |
|---|---|---|---|
| `detect_kind(data)` | `kind.py` | Diz o tipo do arquivo pelo conteúdo | `detect_kind(b"#!/bin/bash\n...")` → `"sh"`; PDF → `None` |
| `parse_elf(data)` | `elf.py` | Lê seções, segmentos e funções importadas de um ELF | `.dyn_imports` → `("socket", "execve")` |
| `extract(kind, data)` | `features.py` | Lista de números que descreve o arquivo | `extract("sh", dados)` → `[1.0, 0.0, ...]` |
| `parse_model(raw)` / `load_model(path, ...)` | `model.py` | Abre o modelo conferindo tudo; erro vira `ModelError` | Modelo com índice inválido → `ModelError` |
| `Model.probability(x)` | `model.py` | Nota de 0 a 1 | `0.97` |
| `top_reasons(model, x)` | `explain.py` | Os motivos que mais pesaram | `"compactado com UPX"` |
| `DpkgKnownGood.contains(data)` | `knowngood.py` | `True` se for cópia de arquivo de pacote | Cópia de `/usr/bin/ls` → `True` |
| `decide(policy, nota, ...)` | `decision.py` | Faixa e se isola | `("alto", True)` |
| `Classifier.score(data, path=...)` | `ml/__init__.py` | Junta tudo: tipo, nota, motivos, faixa | Devolve um `Verdict` |
| `load_default(modo)` | `ml/__init__.py` | Carrega os modelos instalados | Sem modelo → `"nenhum modelo instalado"` |
| `verdict_alert(v, path)` | `alerts.py` | Transforma a decisão num alerta `ml.*` | Faixa `alto` → `ml.malware` (HIGH) |

Mudanças em arquivos que já existiam:

- `detectors/static.py`: o `StaticScanner` chama o classificador com os **mesmos bytes** que já leu (sem leitura
  extra).
- `engine.py`: alerta `ml.*` só isola com `ml_isolate`; fora do isolamento, respeita a lista de confiança.
- `config.py`: seção `[ml]`.
- `cli.py`: liga o classificador no `monitor` e no `scan`; grava o modo sombra.
- `telemetry/`: o relatório leva a nota do modelo.

---

## 10. Perguntas frequentes

**O computador vai ficar mais lento?**
Não. São cerca de 13 ms por programa ou script novo, e arquivos comuns (fotos, documentos) são descartados quase sem
custo. Num dia normal, isso dá menos de 1 segundo de CPU.

**A IA pode apagar um arquivo meu por engano?**
Ela nunca apaga nada: no máximo isola, e só com nota muito alta, com o modo `isolate` ligado e com o modelo aprovado
na prova. Um isolamento é sempre desfeito com "Confio". E a meta do treino é errar no máximo 1 vez em 2.000.

**Por que o mesmo arquivo dá `alto` em Downloads e `medio` no `/tmp`?**
Porque no `/tmp` cai muita coisa legítima, e lá o modelo precisa de mais certeza. Veja a [seção 3](#3-como-ele-decide).

**Como sei se um isolamento foi da IA ou de uma regra?**
O alerta da IA começa com `IA:` e a regra é `ml.malware` ou `ml.malware_reforco`.

**Posso desligar?**
Sim: `[ml] enabled = false` ou `mode = "off"` em `/etc/mandacaru/config.toml`.

**Ele manda meus arquivos para algum lugar?**
Não. A decisão é 100 % local. A telemetria, se você a ligou, leva só a versão do modelo e a nota.

**Ele usa ChatGPT, DeepSeek ou outro modelo de linguagem?**
Não. Usa um modelo pequeno de árvores de decisão, que roda em Python puro e não pode ser enganado por textos
escondidos no malware.

---

## 11. Glossário

| Termo | O que significa |
|---|---|
| **Árvore de decisão** | Sequência de perguntas do tipo "está compactado?" que leva a uma resposta |
| **Característica** | Número que descreve algo do arquivo (tamanho, entropia, se tem certo texto) |
| **Classificador** | Programa que separa coisas em grupos; aqui, "malware" ou "legítimo" |
| **Confiança / nota** | De 0 a 100 %: o quanto o modelo acha que o arquivo é malware |
| **dpkg** | Sistema do Ubuntu/Debian que registra os pacotes instalados e a impressão digital de cada arquivo |
| **ELF** | Formato dos programas executáveis no Linux, o equivalente ao `.exe` do Windows |
| **Entropia** | Medida de "desordem" dos bytes; conteúdo compactado ou cifrado tem entropia alta |
| **Falso positivo** | Arquivo legítimo tratado como malware |
| **Faixa** | Grupo de notas (`alto`, `reforco`, `medio`, `baixo`) que define o que acontece |
| **Hash** | "Impressão digital" de um arquivo, calculada a partir do conteúdo |
| **IoT** | "Internet das coisas": roteadores, câmeras e outros aparelhos; usam muito ARM e MIPS |
| **JSON** | Formato de texto para guardar dados organizados; o modelo é guardado assim |
| **Lista de confiança** | Hashes que você liberou com "Confio"; nunca mais são julgados |
| **Malware** | Programa malicioso: vírus, minerador escondido, ransomware etc. |
| **MITRE ATT&CK** | Catálogo mundial das técnicas de ataque; cada uma tem um código (ex.: T1496, mineração) |
| **Modelo** | O "cérebro" treinado que transforma as características numa nota |
| **Modo sombra** | O modelo calcula e anota o que faria, sem agir, para medir erros na máquina real |
| **Pickle** | Formato do Python que pode executar código ao abrir; por isso é proibido para o modelo |
| **Prova de qualidade (portão)** | Metas que o modelo precisa cumprir antes de poder isolar |
| **Quarentena** | Área isolada para onde o Mandacaru move arquivos perigosos |
| **Regra YARA** | Regra escrita à mão que reconhece malware por textos e padrões |
| **Script** | Programa em texto (shell, Python, Perl, JavaScript, PHP) |
| **Símbolos** | Nomes internos das funções de um programa; malware costuma vir sem eles |
| **Treino** | Mostrar ao modelo milhares de exemplos para ele aprender a separar malware de legítimo |
| **UPX** | Programa que compacta executáveis; muito usado por malware para esconder o conteúdo |
