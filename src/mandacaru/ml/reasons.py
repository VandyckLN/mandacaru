"""Frase curta (sem acento, padrao do projeto) e tecnica MITRE de cada caracteristica.

Uma arvore pode empurrar a nota para cima pelo lado "contrario" de um corte (ex.: tem_symtab=1). A frase so
vale quando o valor do arquivo confirma o que ela afirma: CONDITIONS diz qual e o teste; sem entrada, vale > 0.
"""
from __future__ import annotations

REASONS: dict[str, tuple[str, str | None]] = {
    # ELF
    "tamanho_log2": ("tamanho do arquivo", None),
    "entropia_cabeca": ("conteudo inicial embaralhado", "T1027"),
    "entropia_max_secao": ("secao compactada ou cifrada", "T1027"),
    "classe64": ("programa de 64 bits", None),
    "big_endian": ("formato big-endian (comum em roteadores)", None),
    "tipo_dyn": ("executavel independente de posicao", None),
    "arch_x86_64": ("arquitetura x86-64", None),
    "arch_arm": ("arquitetura ARM (comum em IoT)", None),
    "arch_mips": ("arquitetura MIPS (comum em roteadores)", None),
    "arch_outra": ("arquitetura incomum", None),
    "n_secoes": ("numero de secoes", None),
    "n_segmentos": ("numero de segmentos", None),
    "sem_tabela_secoes": ("sem tabela de secoes", "T1027"),
    "dinamico": ("ligacao dinamica", None),
    "segmento_wx": ("memoria gravavel e executavel", "T1027"),
    "entrada_fora_text": ("inicio fora do codigo normal", "T1027"),
    "entrada_ultima_secao": ("inicio na ultima secao", "T1027"),
    "sobra_pos_estruturas_log2": ("dados escondidos no fim do arquivo", "T1027"),
    "upx": ("compactado com UPX", "T1027"),
    "secoes_anomalas": ("secoes com nomes incomuns", "T1027"),
    "tem_symtab": ("sem simbolos", "T1027"),
    "n_importacoes": ("poucas ou muitas funcoes importadas", None),
    "imp_rede": ("usa funcoes de rede", None),
    "imp_processo": ("cria processos ou executa comandos", "T1059"),
    "imp_privilegio": ("mexe em privilegios ou depuracao", "T1548"),
    "imp_arquivo": ("apaga ou altera arquivos", None),
    "imp_sinal": ("envia sinais a outros processos", None),
    "n_strings_log2": ("quantidade de textos internos", None),
    "strings_tam_medio": ("tamanho dos textos internos", None),
    # scripts
    "tipo_sh": ("script de shell", None),
    "tipo_python": ("script Python", None),
    "tipo_perl": ("script Perl", None),
    "tipo_js": ("script JavaScript", None),
    "tipo_php": ("script PHP", None),
    "tem_shebang": ("linha #! de execucao", None),
    "linhas_log2": ("numero de linhas", None),
    "maior_linha_log2": ("linha muito longa", "T1027"),
    "entropia": ("conteudo embaralhado", "T1027"),
    "nao_alnum": ("muitos simbolos fora do comum", "T1027"),
    "blocos_b64": ("blocos longos em base64", "T1027"),
    "maior_b64_log2": ("bloco base64 muito longo", "T1027"),
    "blocos_hex": ("blocos longos em hexadecimal", "T1027"),
    "escapes_hex": ("muitas sequencias \\x..", "T1027"),
    "char_codes": ("texto montado por codigos de caractere", "T1027"),
    "exec_dinamico": ("executa codigo montado na hora", "T1059"),
    "decodificacao": ("decodifica conteudo escondido", "T1140"),
    "baixa_e_executa": ("baixa da internet e executa", "T1105"),
    # comuns
    "ind_mineracao": ("endereco de pool de mineracao", "T1496"),
    "ind_persistencia": ("se instala para iniciar sozinho", "T1053"),
    "ind_credenciais": ("procura senhas ou chaves", "T1552"),
    "ind_antianalise": ("tenta escapar de analise", "T1622"),
    "ind_download": ("baixa arquivos da internet", "T1105"),
    "ind_execucao": ("prepara execucao em segundo plano", "T1059"),
    "ind_sabotagem": ("desliga protecoes do sistema", "T1562"),
    "ind_autoapagamento": ("apaga a si mesmo", "T1070"),
    "ind_esconderijo": ("usa pastas ou historico escondidos", "T1564"),
    "ind_resgate": ("texto de resgate", "T1486"),
    "ind_shell_reverso": ("padrao de shell reverso", "T1059"),
    "ind_prompt_injection": ("instrucoes para enganar agentes de IA", None),
    "ip_literais": ("enderecos IP fixos", None),
    "urls": ("enderecos de internet", None),
    "user_agent": ("se passa por navegador", None),
}


# caracteristica -> (operador, limite). Padrao: (">", 0) — a frase afirma presenca.
CONDITIONS: dict[str, tuple[str, float]] = {
    "tem_symtab": ("==", 0.0),                 # "sem simbolos"
    "entropia_cabeca": (">=", 7.0),
    "entropia_max_secao": (">=", 7.0),
    "entropia": (">=", 6.0),
    "nao_alnum": (">=", 0.3),
    "maior_linha_log2": (">=", 10.0),          # 1 KB ou mais numa linha
    "n_importacoes": ("any", 0.0),
    "n_secoes": ("any", 0.0),
    "n_segmentos": ("any", 0.0),
    "tamanho_log2": ("any", 0.0),
    "linhas_log2": ("any", 0.0),
    "n_strings_log2": ("any", 0.0),
    "strings_tam_medio": ("any", 0.0),
}


def applies(feature: str, value: float) -> bool:
    """A frase de `feature` e verdadeira para este valor?"""
    op, limit = CONDITIONS.get(feature, (">", 0.0))
    if op == "any":
        return True
    if op == "==":
        return value == limit
    if op == ">=":
        return value >= limit
    return value > limit
