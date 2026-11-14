/*
  Regras base do Mandacaru. Foco: tecnicas que scripts gerados por LLM
  costumam repetir mesmo quando o codigo muda a cada geracao.
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
    strings:
        $r1 = "/dev/tcp/"
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
    strings:
        $a = "your files have been encrypted" nocase
        $b = "seus arquivos foram criptografados" nocase
        $c = "bitcoin" nocase
        $d = "decrypt" nocase
        $e = ".onion" nocase
    condition:
        ($a or $b) and 1 of ($c, $d, $e)
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
