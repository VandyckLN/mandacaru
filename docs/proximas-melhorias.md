# Próximas melhorias

Ideias aprovadas pelo dono e ainda não planejadas. Cada uma vira spec + plano quando for a vez dela.

## VirusTotal no botão "Analisar" (por hash)

Anotada em 2026-11-25.

- **O quê:** acrescentar o VirusTotal (API v3, `GET /api/v3/files/{sha256}`) como terceira fonte do botão **Analisar**, junto do Team Cymru MHR e do CIRCL hashlookup, mostrando "N de M antivírus marcam como malicioso".
- **Só por hash. Nunca enviar o arquivo.** O que é enviado ao VirusTotal fica disponível para assinantes pagos, e isso vazaria arquivos e código do usuário.
- **Chave do próprio usuário,** colada nas Configurações e guardada só na máquina dele. Sem chave, a fonte não aparece. A API pública não pode ser embutida num produto com chave compartilhada.
- **Respeitar a cota pública** (4 consultas por minuto, 500 por dia): fila com espera, e mensagem clara quando a cota acabar.
- **Fora do escopo:** "Verificar projeto". O VirusTotal não detecta técnicas em arquivos de texto (prompt injection, tarefas do VS Code, workflows), e para bibliotecas o OSV.dev já cobre falhas e pacotes maliciosos.
