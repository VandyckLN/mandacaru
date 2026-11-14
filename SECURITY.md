# Política de segurança

O Mandacaru é uma ferramenta de defesa. Uma falha nele pode deixar uma máquina desprotegida, então tratamos relatos de segurança com prioridade.

## Como relatar

**Não abra uma issue pública.** Use o relato privado do GitHub:
<https://github.com/VandyckLN/mandacaru/security/advisories/new>

Inclua a versão (`mandacaru --version`), o sistema, os passos para reproduzir e o impacto.

## O que conta como falha de segurança

- Evasão: uma técnica que deveria ser detectada por uma regra existente e passa sem alerta.
- Execução de código, escalada de privilégio ou negação de serviço no próprio agente (por exemplo, um arquivo que derruba a varredura).
- Vazamento de dados pelos alertas ou logs.

Falso positivo não é falha de segurança: abra uma issue comum.

## Versões com correção

Enquanto o projeto estiver em 0.x, só a última versão publicada recebe correções.
