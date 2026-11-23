# Pendências do classificador de IA

O que ficou para depois. Marque `[x]` quando fizer.

## Antes da Tarefa 14 (conferir falsos positivos nos seus arquivos)

- [x] `mandacaru ml avaliar --jsonl` imprimir cada linha na hora, em vez de só no fim. Hoje, um Ctrl-C ou um erro no meio de uma lista grande perde tudo.
- [x] `--stdin`: tirar o `\r` de entradas com CRLF; recusar `--json` e `--jsonl` juntos; caminhos com bytes inválidos em UTF-8.

## Decisão sua

- [ ] Portão de qualidade: com 6.000 legítimos no teste, a meta "FP ≤ 0,05 %" aceita até 3 falsos positivos. A "regra dos três" da spec só vale com zero erros. Decidir se a meta passa a ser o limite superior (95 % de confiança) ≤ 0,05 %.

## Melhorias menores (do revisor final)

- [ ] Corpus: linha do manifesto que não é objeto JSON (`null`, `[]`) impede o corpus de abrir.
- [ ] Corpus: escrever a linha do manifesto em laço (gravação parcial com disco cheio).
- [ ] Teto de disco: contar o tamanho do zip também (hoje um zip de até 9 MB conta 1 byte); parar de baixar perto do teto.
- [ ] Coleta: tratar erro de rede e timeout (hoje traceback, sem vazar a chave); não dormir depois da última tentativa.
- [ ] Coleta: estratificar o catálogo por tipo e data.
- [ ] Legítimos: pular o resto do membro `ar` com `seek` em vez de ler para a memória.
- [ ] Treino usa 2 s por arquivo; o antivírus, 0,25 s (detecção medida fica um pouco otimista).
- [ ] Teste de política: pegar também `asyncio.create_subprocess_*`, `getattr(os, "system")`, `builtins.exec`, `_posixsubprocess`, `_ctypes`, `runpy`, `copyfileobj` de `zf.open`.
- [ ] `instalar_modelo.py`: recusar golden vazio e vetor de tamanho errado; filtrar controles C1 e bidi; conferir `data_manifest_sha256`; instalar de forma atômica.
- [ ] Treino: separar a validação do early stopping antes de repetir as linhas difíceis.
- [ ] Nome `feature_code_sha`: é hash dos arquivos, não o commit que a spec descreve (ajustar código ou spec).

## Parte B do Plano 2 (operação, precisa de você)

- [ ] Tarefa 11: proteger a UbuntuPentest e o bubblewrap (root nessa distro). Confirmar o formato real do `full.csv.zip`.
- [ ] Tarefa 12: coleta (sua chave grátis do MalwareBazaar, alguns dias).
- [ ] Tarefa 13: extração e treino sem rede.
- [ ] Tarefa 14: trazer o modelo e conferir falsos positivos nos seus arquivos.
- [ ] Tarefa 15: lançar a 0.6.0 em modo sombra (`sudo`, 2 a 4 semanas).
- [ ] Tarefa 16: trocar o padrão para isolar.
