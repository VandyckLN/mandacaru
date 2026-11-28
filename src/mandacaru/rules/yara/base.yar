/*
  Regras base do Mandacaru. Foco: tecnicas que scripts gerados por LLM
  costumam repetir mesmo quando o codigo muda a cada geracao.

  meta.category define o rebaixamento em arquivos de texto (static.py):
    "technique" -> no maximo MEDIUM em .md/.txt/.jsonl/.log/.rst (docs e
                   transcricoes descrevem ataques sem executa-los)
    "note"      -> idem, exceto .txt (formato tipico de nota de resgate)
  Regras sem category (familia, hash, as do usuario) nunca sao rebaixadas.
*/

rule EICAR_Test_File
{
    meta:
        description = "Arquivo de teste EICAR (padrao da industria)"
        severity = "LOW"
    strings:
        $e = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $e
}

rule Py_Exec_Decoded_Payload
{
    meta:
        description = "Python executando payload decodificado (base64/zlib/marshal)"
        severity = "HIGH"
        mitre = "T1027,T1059.006"
        category = "technique"
    strings:
        // a decodificacao acontece dentro da propria chamada exec()/eval()
        $nested = /\b(exec|eval)\s*\(\s*[\w.]*(b64decode|b32decode|a85decode|decompress|marshal\.loads|fromhex|codecs\.decode)\s*\(/
    condition:
        $nested
}

rule PS_Encoded_Or_Download_Exec
{
    meta:
        description = "PowerShell com comando codificado ou download seguido de execucao"
        severity = "HIGH"
        mitre = "T1059.001,T1105"
        category = "technique"
    strings:
        $enc = /(powershell|pwsh)(\.exe)?[^\n]{0,80}\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $iex = /\b(iex|invoke-expression)\b/ nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "Invoke-WebRequest" nocase
        $dl3 = "Net.WebClient" nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
    condition:
        $enc or ($iex and 1 of ($dl*)) or ($bypass and 1 of ($dl*))
}

rule Shell_Pipe_To_Interpreter
{
    meta:
        description = "Download direto para um interpretador (curl|sh, wget|bash, ...)"
        severity = "MEDIUM"
        mitre = "T1105,T1059.004"
        category = "technique"
    strings:
        $p = /(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
        $q = /(curl|wget)[^\n|]{0,200}\|\s*python[23]?\b/
    condition:
        any of them
}

rule Reverse_Shell_Patterns
{
    meta:
        description = "Padroes classicos de shell reverso"
        severity = "CRITICAL"
        mitre = "T1059"
        category = "technique"
    strings:
        // /dev/tcp sozinho aparece em changelogs e listas de indicadores; exige o
        // redirecionamento de shell que abre o socket (>&, &>, <>, <, >)
        $r1 = /(<>|>&|&>|<|>)\s*\/dev\/(tcp|udp)\/[^\s\/]+\/\S+/
        $r2 = /nc(at)?\s+(-e|-c)\s*\/bin\/(ba)?sh/
        $r3 = /socket\.socket\(.{0,200}(dup2|pty\.spawn)/
        $r4 = /mkfifo\s+\S+;\s*(cat|tail)\s+\S+\s*\|\s*\/bin\/(ba)?sh/
    condition:
        any of them
}

rule Ransom_Note_Keywords
{
    meta:
        description = "Texto tipico de nota de resgate"
        severity = "HIGH"
        mitre = "T1486"
        category = "note"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "seus arquivos foram criptografados" nocase
        // frases de instrucao da nota, nao palavras soltas (bitcoin/decrypt aparecem em codigo)
        $pay = /\b(pay|send|pague|envie|transfira)\s[^\n]{0,40}\b(bitcoin|btc|monero|xmr)\b/ nocase
        $rec = /\b(to (decrypt|recover|restore) (all )?your files|para (descriptografar|recuperar|restaurar) (todos )?(os )?seus arquivos)\b/ nocase
        $tor = /\b[a-z2-7]{16,56}\.onion\b/ nocase
    condition:
        ($a or $b) and ($pay or $rec or $tor)
}

rule Prompt_Injection_Instructions
{
    meta:
        description = "Instrucoes de prompt injection embutidas em arquivo (ataque a agentes de IA)"
        severity = "MEDIUM"
        mitre = "T1204"
    strings:
        $i1 = "ignore all previous instructions" nocase
        $i2 = "ignore previous instructions" nocase
        $i3 = "ignore as instrucoes anteriores" nocase
        $i4 = "you are now in developer mode" nocase
        $i5 = "do not tell the user" nocase
        $i6 = "nao conte ao usuario" nocase
        $act1 = /(send|upload|exfiltrate|envie|post)\b.{0,80}(ssh|\.env|token|api[_ ]?key|password|senha|credential)/ nocase
        $ai = /\b(assistant|assistente|ai agent|agente de ia|llm|language model|modelo de linguagem|claude|chatgpt|copilot)\b/ nocase
    condition:
        1 of ($i*) or
        // pedido de exfiltracao endereçado a uma IA, a ate 300 bytes de distancia
        (filesize < 2MB and for any i in (1..#act1) : (
            for any j in (1..#ai) : (@ai[j] - @act1[i] < 300 and @act1[i] - @ai[j] < 300)))
}

rule JS_Exec_Decoded_Payload
{
    meta:
        description = "JavaScript executando payload decodificado (atob/Buffer.from)"
        severity = "HIGH"
        mitre = "T1027,T1059.007"
        category = "technique"
    strings:
        $eval_atob = /\beval\s*\(\s*atob\s*\(/
        $eval_buf = /\beval\s*\(\s*Buffer\.from\s*\([^)\n]{1,200}['"](base64|hex)['"]/
        $fn_atob = /\bnew\s+Function\s*\([^)\n]{0,120}\batob\s*\(/
        $fn_buf = /\bnew\s+Function\s*\([^)\n]{0,120}\bBuffer\.from\s*\([^)\n]{1,200}['"](base64|hex)['"]/
    condition:
        any of them
}

rule Cron_Persistence_From_Script
{
    meta:
        description = "Script instalando tarefa agendada no crontab (persistencia)"
        severity = "MEDIUM"
        mitre = "T1053.003"
        category = "technique"
    strings:
        $pipe = /\|\s*crontab\s+-(\s|$|;|#)/
        $tmp = /\bcrontab\s+(\/tmp|\/var\/tmp|\/dev\/shm)\/\S+/
    condition:
        any of them
}

rule Win_LOLBin_Download_Exec
{
    meta:
        description = "Utilitario nativo do Windows (LOLBin) baixando ou executando payload remoto"
        severity = "HIGH"
        mitre = "T1105,T1218"
        category = "technique"
    strings:
        $certutil = /\bcertutil(\.exe)?\b[^\n]{0,120}-urlcache[^\n]{0,120}https?:\/\// nocase
        $mshta = /\bmshta(\.exe)?\s+["']?https?:\/\// nocase
        $regsvr = /\bregsvr32(\.exe)?\b[^\n]{0,100}\/i:https?:\/\/[^\n]{0,120}scrobj\.dll/ nocase
        $bits = /\bbitsadmin(\.exe)?\b[^\n]{0,80}\/transfer\b[^\n]{0,160}https?:\/\// nocase
    condition:
        any of them
}

rule Win_Persistence_Registry_Or_Task
{
    meta:
        description = "Script configurando persistencia no Windows (Registro Run ou tarefa agendada)"
        severity = "MEDIUM"
        mitre = "T1547.001,T1053.005"
        category = "technique"
    strings:
        $reg_run = /\breg(\.exe)?\s+add\b[^\n]{0,160}\\CurrentVersion\\Run(Once)?\b/ nocase
        $schtasks = /\bschtasks(\.exe)?\s+\/create\b[^\n]{0,200}\/tr\s+["']?[^\n]{0,120}(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|\\temp\\|%temp%|%appdata%)/ nocase
    condition:
        any of them
}

rule Prompt_Injection_Hidden_Unicode
{
    meta:
        description = "Texto oculto com caracteres Unicode Tags (possivel prompt injection invisivel)"
        severity = "MEDIUM"
        mitre = "T1027,T1204"
    strings:
        // sequencia longa (12+) de caracteres U+E0000..U+E007F (acima de emojis de bandeira, que usam ate 7)
        $tags = /(\xf3\xa0\x80[\x80-\xbf]|\xf3\xa0\x81[\x80-\xbf]){12,}/
    condition:
        filesize < 2MB and $tags
}
