"""
Entrega 3 - Varredura de portas e serviços
Disciplina: Segurança da Informação (UNIT)

Cenário: a equipe precisa avaliar quais serviços de um ambiente de homologação estão expostos.

O script automatiza uma varredura controlada com Nmap:
  - só executa se a autorização e o escopo estiverem registrados em escopo.json
  - recusa alvos fora do escopo e qualquer endereço que não seja privado/loopback
  - roda quatro fases (descoberta, TCP completo, serviços/versões, UDP) e guarda as evidências
  - gera a tabela porta / protocolo / serviço / necessário / risco / recomendação
  - compara duas varreduras (antes e depois da redução da superfície de ataque)

Uso:
  python varredura.py escanear --alvo 192.168.56.101 --rotulo antes
  python varredura.py tabela evidencias/antes
  python varredura.py comparar evidencias/antes evidencias/depois
"""
import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ESCOPO_PADRAO = BASE_DIR / "escopo.json"
NECESSIDADE_PADRAO = BASE_DIR / "necessidade.json"
EVID_DIR = BASE_DIR / "evidencias"

MAX_ENDERECOS = 256

NIVEIS = {"Alto": 3, "Médio": 2, "Baixo": 1}

REGRAS = {
    "ftp": ("Alto", "Protocolo sem criptografia: usuário e senha trafegam em texto puro",
            "Desativar; transferir arquivos por SFTP (sobre SSH) ou FTPS"),
    "telnet": ("Alto", "Protocolo sem criptografia e sem integridade",
               "Desativar; usar SSH"),
    "tftp": ("Alto", "Sem autenticação nem criptografia", "Desativar ou restringir a uma rede de gerência"),
    "mysql": ("Alto", "Banco de dados acessível pela rede", "Vincular a 127.0.0.1 ou a uma rede interna e filtrar no firewall"),
    "postgresql": ("Alto", "Banco de dados acessível pela rede", "Vincular a 127.0.0.1 ou a uma rede interna e filtrar no firewall"),
    "ms-sql-s": ("Alto", "Banco de dados acessível pela rede", "Filtrar no firewall e restringir a hosts da aplicação"),
    "mongodb": ("Alto", "Banco de dados acessível pela rede", "Vincular a 127.0.0.1 e exigir autenticação"),
    "redis": ("Alto", "Armazenamento em memória sem autenticação por padrão", "Vincular a 127.0.0.1 e exigir senha"),
    "memcached": ("Alto", "Sem autenticação por padrão", "Vincular a 127.0.0.1"),
    "vnc": ("Alto", "Acesso remoto gráfico com autenticação fraca", "Desativar ou tunelar por SSH/VPN"),
    "ms-wbt-server": ("Alto", "Área de trabalho remota exposta", "Restringir por VPN/firewall e exigir NLA e MFA"),
    "microsoft-ds": ("Alto", "SMB exposto: alvo comum de movimentação lateral e exploração", "Bloquear no firewall; manter SMB assinado e sem SMBv1"),
    "netbios-ssn": ("Alto", "NetBIOS/SMB legado exposto", "Desativar ou bloquear no firewall"),
    "nfs": ("Alto", "Compartilhamento de arquivos pela rede", "Restringir exports por host e usar rede interna"),
    "rexec": ("Alto", "Execução remota sem criptografia", "Desativar; usar SSH"),
    "rlogin": ("Alto", "Login remoto sem criptografia", "Desativar; usar SSH"),
    "rsh": ("Alto", "Shell remoto sem criptografia", "Desativar; usar SSH"),
    "ssh": ("Médio", "Acesso remoto administrativo: alvo frequente de ataques de força bruta",
            "Autenticação por chave, sem login de root, origem restrita e limite de tentativas"),
    "http": ("Médio", "Tráfego sem criptografia e possível vazamento de versão",
             "Servir por HTTPS, redirecionar HTTP, ocultar versão e manter atualizado"),
    "http-proxy": ("Médio", "Proxy exposto pode ser abusado", "Restringir a clientes autorizados"),
    "https": ("Baixo", "Serviço web com criptografia", "Manter TLS atual (1.2+), certificados válidos e cabeçalhos de segurança"),
    "ssl": ("Baixo", "Serviço com criptografia", "Manter TLS atual e certificados válidos"),
    "smtp": ("Médio", "Pode permitir relay ou enumeração de usuários", "Exigir autenticação e TLS; restringir relay"),
    "pop3": ("Médio", "Credenciais em texto puro se sem TLS", "Usar POP3S ou desativar"),
    "imap": ("Médio", "Credenciais em texto puro se sem TLS", "Usar IMAPS ou desativar"),
    "domain": ("Médio", "Resolvedor DNS exposto pode ser abusado em amplificação", "Restringir consultas a clientes internos"),
    "snmp": ("Médio", "Comunidades padrão revelam informações do host", "Usar SNMPv3 ou desativar"),
    "ldap": ("Médio", "Diretório exposto pode revelar usuários", "Restringir e exigir LDAPS"),
    "rpcbind": ("Médio", "Revela serviços RPC disponíveis", "Desativar se não houver NFS/RPC em uso"),
    "netbios-ns": ("Médio", "Revela nomes e informações da rede", "Desativar ou bloquear no firewall"),
    "netbios-dgm": ("Médio", "Revela informações da rede", "Desativar ou bloquear no firewall"),
    "ssdp": ("Médio", "Descoberta UPnP pode ser abusada", "Desativar se não necessário"),
    "ntp": ("Baixo", "Serviço de tempo; evitar consultas de gerência abertas", "Restringir monitoramento remoto"),
    "mdns": ("Baixo", "Descoberta local de serviços", "Desativar em servidores"),
    "dhcpc": ("Baixo", "Cliente DHCP", "Sem ação, se esperado"),
}

SSH_ALGORITMOS_FRACOS = {
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
    "ssh-rsa", "ssh-dss", "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc",
    "cast128-cbc", "arcfour", "arcfour128", "arcfour256", "hmac-md5", "hmac-md5-96", "hmac-sha1",
    "hmac-sha1-96", "umac-64@openssh.com",
}


class ErroEscopo(Exception):
    pass


# ------------------------------------------------------------ autorização e escopo
def carregar_escopo(caminho=ESCOPO_PADRAO) -> dict:
    caminho = Path(caminho)
    if not caminho.exists():
        raise ErroEscopo(f"Arquivo de escopo não encontrado: {caminho}")
    try:
        dados = json.loads(caminho.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ErroEscopo(f"escopo.json inválido: {e}")

    aut = dados.get("autorizacao", {})
    try:
        date.fromisoformat(str(aut.get("data", "")))
    except ValueError:
        raise ErroEscopo("Registre a data da autorização (AAAA-MM-DD) em escopo.json")
    if not aut.get("responsaveis"):
        raise ErroEscopo("Informe os responsáveis pela autorização em escopo.json")

    redes = []
    for texto in dados.get("redes_autorizadas", []):
        try:
            rede = ipaddress.ip_network(texto, strict=True)
        except ValueError:
            raise ErroEscopo(f"Rede inválida em escopo.json: {texto}")
        if not (rede.is_private or rede.is_loopback):
            raise ErroEscopo(f"A rede {rede} não é privada: apenas laboratório local é permitido")
        redes.append(rede)
    if not redes:
        raise ErroEscopo("Informe ao menos uma rede em redes_autorizadas")

    dados["_redes"] = redes
    return dados


def validar_alvo(alvo: str, redes) -> ipaddress._BaseNetwork:
    try:
        rede = ipaddress.ip_network(alvo, strict=True)
    except ValueError:
        raise ErroEscopo("Alvo inválido: use um IP ou uma rede CIDR sem bits de host (ex.: 192.168.56.0/24); nomes de host não são aceitos")
    if rede.num_addresses > MAX_ENDERECOS:
        raise ErroEscopo(f"Alvo muito grande: o máximo é {MAX_ENDERECOS} endereços")
    if not any(rede.version == r.version and rede.subnet_of(r) for r in redes):
        raise ErroEscopo(f"O alvo {alvo} está fora do escopo autorizado")
    return rede


# ------------------------------------------------------------------- Nmap
def eh_privilegiado() -> bool:
    if os.name == "nt":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def localizar_nmap() -> str:
    caminho = shutil.which("nmap")
    if not caminho:
        raise ErroEscopo("Nmap não encontrado no PATH. Instale em https://nmap.org/download")
    return caminho


def versao_nmap(nmap: str) -> str:
    saida = subprocess.run([nmap, "--version"], capture_output=True, text=True).stdout
    return saida.splitlines()[0].strip() if saida else "desconhecida"


def cmd_descoberta(nmap, alvo, base):
    return [nmap, "-sn", "-n", "-oA", f"{base}_01_descoberta", alvo]


def cmd_tcp(nmap, alvos, base, privilegiado, tcp_connect):
    tipo = "-sS" if privilegiado and not tcp_connect else "-sT"
    return [nmap, tipo, "-Pn", "-n", "-p-", "--open", "--reason", "-T3", "-oA", f"{base}_02_tcp_completo", *alvos]


def cmd_servicos(nmap, alvos, base, portas):
    lista = ",".join(str(p) for p in sorted(portas))
    return [nmap, "-sV", "--version-intensity", "5",
            "--script=default,ssh-auth-methods,ssh2-enum-algos,ssh-hostkey",
            "-Pn", "-n", "--reason", "-p", lista, "-oA", f"{base}_03_servicos", *alvos]


def cmd_udp(nmap, alvos, base):
    return [nmap, "-sU", "--top-ports", "20", "-Pn", "-n", "--open", "--reason", "-T3",
            "-oA", f"{base}_04_udp", *alvos]


def comando_legivel(comando: list, nmap: str) -> str:
    prefixo = str(BASE_DIR) + os.sep
    partes = ["nmap" if parte == nmap else parte.replace(prefixo, "") for parte in comando]
    return " ".join(partes)


def executar(comando: list) -> int:
    print("$ " + " ".join(comando))
    return subprocess.run(comando).returncode


# ------------------------------------------------------------------- leitura de XML
def ler_xml(caminho) -> dict:
    raiz = ET.parse(caminho).getroot()
    hosts = {}
    for h in raiz.findall("host"):
        ip = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if ip is None:
            continue
        status = h.find("status")
        portas = []
        for p in h.findall("ports/port"):
            estado = p.find("state")
            servico = p.find("service")
            scripts = {}
            for s in p.findall("script"):
                scripts[s.get("id")] = s
            portas.append({
                "porta": int(p.get("portid")),
                "protocolo": p.get("protocol"),
                "estado": estado.get("state") if estado is not None else "desconhecido",
                "razao": estado.get("reason", "") if estado is not None else "",
                "servico": servico.get("name", "desconhecido") if servico is not None else "desconhecido",
                "produto": servico.get("product", "") if servico is not None else "",
                "versao": servico.get("version", "") if servico is not None else "",
                "extra": servico.get("extrainfo", "") if servico is not None else "",
                "tunel": servico.get("tunnel", "") if servico is not None else "",
                "scripts": scripts,
            })
        hosts[ip] = {"estado": status.get("state") if status is not None else "desconhecido", "portas": portas}
    return hosts


def hosts_ativos(caminho) -> list:
    return [ip for ip, dados in ler_xml(caminho).items() if dados["estado"] == "up"]


def portas_abertas_tcp(caminho) -> set:
    return {p["porta"] for dados in ler_xml(caminho).values() for p in dados["portas"]
            if p["protocolo"] == "tcp" and p["estado"] == "open"}


def consolidar(pasta) -> dict:
    pasta = Path(pasta)
    tcp = next(iter(sorted(pasta.glob("*_03_servicos.xml"))), None) or next(iter(sorted(pasta.glob("*_02_tcp_completo.xml"))), None)
    udp = next(iter(sorted(pasta.glob("*_04_udp.xml"))), None)
    if tcp is None and udp is None:
        raise FileNotFoundError(f"Nenhum XML de varredura encontrado em {pasta}")
    resultado = {}
    for arquivo in (tcp, udp):
        if arquivo is None:
            continue
        for ip, dados in ler_xml(arquivo).items():
            destino = resultado.setdefault(ip, {"estado": dados["estado"], "portas": []})
            destino["portas"].extend(dados["portas"])
    for dados in resultado.values():
        dados["portas"].sort(key=lambda p: (p["protocolo"], p["porta"]))
    return resultado


# --------------------------------------------------------------- análise e risco
def texto_servico(p: dict) -> str:
    nome = p["servico"] + (" (TLS)" if p["tunel"] == "ssl" and p["servico"] != "https" else "")
    detalhe = " ".join(x for x in (p["produto"], p["versao"]) if x)
    return f"{nome} - {detalhe}" if detalhe else nome


def metodos_ssh(p: dict) -> list:
    script = p["scripts"].get("ssh-auth-methods")
    if script is None:
        return []
    return [e.text for e in script.iter("elem") if e.text]


def algoritmos_ssh(p: dict) -> dict:
    script = p["scripts"].get("ssh2-enum-algos")
    if script is None:
        return {}
    return {t.get("key"): [e.text for e in t.findall("elem") if e.text] for t in script.findall("table")}


def chaves_ssh(p: dict) -> list:
    script = p["scripts"].get("ssh-hostkey")
    if script is None:
        return []
    chaves = []
    for t in script.findall("table"):
        campos = {e.get("key"): e.text for e in t.findall("elem")}
        chaves.append((campos.get("type", "?"), campos.get("bits", "?")))
    return chaves


def carregar_necessidade(caminho=NECESSIDADE_PADRAO) -> dict:
    caminho = Path(caminho)
    if not caminho.exists():
        return {}
    return json.loads(caminho.read_text(encoding="utf-8"))


def classificar(p: dict, necessidade: dict) -> dict:
    chave = f"{p['porta']}/{p['protocolo']}"
    info = necessidade.get(chave)
    necessario = None if info is None else bool(info.get("necessario"))

    risco, motivo, recomendacao = REGRAS.get(
        p["servico"], ("Médio", "Serviço sem regra específica", "Confirmar a necessidade e restringir o acesso"))

    if p["servico"] == "ssh":
        metodos = metodos_ssh(p)
        if metodos and "password" not in metodos and "keyboard-interactive" not in metodos:
            risco = "Baixo"
            motivo = "Somente autenticação por chave pública"
            recomendacao = "Manter; restringir origem e limitar tentativas"
        elif "password" in metodos:
            risco = "Médio"
            motivo = "Aceita autenticação por senha: exposta a força bruta e a senhas reutilizadas"
            recomendacao = "Desabilitar senha e usar chave pública; negar root; restringir origem e limitar tentativas"
    if p["servico"] == "http" and p["tunel"] == "ssl":
        risco, motivo, recomendacao = REGRAS["https"]
    if p["estado"] == "open|filtered":
        motivo = "Estado incerto (open|filtered) em UDP: " + motivo

    if necessario is False:
        recomendacao = "Desativar/bloquear: serviço não necessário. " + recomendacao
        if NIVEIS[risco] < NIVEIS["Médio"]:
            risco = "Médio"

    return {"necessario": necessario, "risco": risco, "motivo": motivo, "recomendacao": recomendacao,
            "justificativa": "" if info is None else info.get("justificativa", "")}


def texto_necessario(valor) -> str:
    return "Não definido" if valor is None else ("Sim" if valor else "Não")


def linhas_tabela(resultado: dict, necessidade: dict) -> list:
    linhas = []
    for ip, dados in resultado.items():
        for p in dados["portas"]:
            if p["estado"] != "open":
                continue
            c = classificar(p, necessidade)
            linhas.append({"ip": ip, "porta": p["porta"], "protocolo": p["protocolo"].upper(), "estado": p["estado"],
                           "servico": texto_servico(p), "necessario": texto_necessario(c["necessario"]),
                           "risco": c["risco"], "motivo": c["motivo"], "recomendacao": c["recomendacao"]})
    linhas.sort(key=lambda x: (x["ip"], x["protocolo"], x["porta"]))
    return linhas


def linhas_incertas(resultado: dict) -> list:
    itens = []
    for ip, dados in resultado.items():
        for p in dados["portas"]:
            if p["estado"] == "open|filtered":
                itens.append({"ip": ip, "porta": p["porta"], "protocolo": p["protocolo"].upper(),
                              "servico": p["servico"]})
    itens.sort(key=lambda x: (x["ip"], x["protocolo"], x["porta"]))
    return itens


LIMITE_NOTA_FIREWALL = 10


def tabela_incertas_markdown(itens: list) -> str:
    if not itens:
        return "_Nenhuma porta com estado incerto._"
    cab = "| Host | Porta | Protocolo | Serviço provável |\n|---|---|---|---|"
    corpo = [f"| {i['ip']} | {i['porta']} | {i['protocolo']} | {i['servico']} |" for i in itens]
    return cab + "\n" + "\n".join(corpo)


NOTA_UDP = ("O UDP não tem handshake: quando a porta não responde, o Nmap não consegue distinguir uma porta aberta "
            "de uma porta filtrada (estado `open|filtered`). Estas portas **não estão confirmadas como abertas**.")
NOTA_FIREWALL = ("A grande quantidade de portas `open|filtered` sem resposta é o comportamento típico de um firewall que "
                 "descarta pacotes (política DROP): sem a resposta \"porta fechada\", todas as portas ficam inconclusivas. "
                 "Isso não indica que os serviços estejam ativos.")


def tabela_markdown(linhas: list) -> str:
    if not linhas:
        return "_Nenhuma porta aberta encontrada._"
    cab = "| Host | Porta | Protocolo | Serviço | Necessário? | Risco | Recomendação |\n|---|---|---|---|---|---|---|"
    corpo = [f"| {l['ip']} | {l['porta']} | {l['protocolo']} | {l['servico']} | {l['necessario']} | "
             f"{l['risco']} | {l['recomendacao']} |" for l in linhas]
    return cab + "\n" + "\n".join(corpo)


def analise_ssh(resultado: dict) -> str:
    saidas = []
    for ip, dados in resultado.items():
        for p in dados["portas"]:
            if p["servico"] != "ssh" or p["estado"] != "open":
                continue
            saidas.append(f"### SSH em {ip}:{p['porta']}")
            saidas.append(f"- Versão: {' '.join(x for x in (p['produto'], p['versao']) if x) or 'não identificada'}")
            metodos = metodos_ssh(p)
            saidas.append("- Métodos de autenticação aceitos: " + (", ".join(metodos) if metodos else "não coletado"))
            if "password" in metodos:
                saidas.append("  - Achado: autenticação por senha habilitada")
            chaves = chaves_ssh(p)
            if chaves:
                saidas.append("- Chaves do host: " + ", ".join(f"{t} ({b} bits)" for t, b in chaves))
                for t, b in chaves:
                    if "dss" in t or (t.startswith("ssh-rsa") and b.isdigit() and int(b) < 2048):
                        saidas.append(f"  - Achado: chave de host fraca ({t}, {b} bits)")
            else:
                saidas.append("- Chaves do host: não coletadas (o script ssh-hostkey não retornou chaves)")
            algoritmos = algoritmos_ssh(p)
            fracos = sorted({a for lista in algoritmos.values() for a in lista if a in SSH_ALGORITMOS_FRACOS})
            if algoritmos:
                saidas.append("- Algoritmos fracos oferecidos: " + (", ".join(fracos) if fracos else "nenhum"))
            else:
                saidas.append("- Algoritmos: não coletado")
    if not saidas:
        return "_Nenhum serviço SSH encontrado._"
    return "\n".join(saidas)


def resumo_risco(linhas: list, incertas: list = ()) -> str:
    contagem = {n: sum(1 for l in linhas if l["risco"] == n) for n in ("Alto", "Médio", "Baixo")}
    desnecessarias = sum(1 for l in linhas if l["necessario"] == "Não")
    return (f"- Portas abertas (confirmadas): {len(linhas)}\n- Risco Alto: {contagem['Alto']}, Médio: {contagem['Médio']}, "
            f"Baixo: {contagem['Baixo']}\n- Expostas e não necessárias: {desnecessarias}\n"
            f"- Portas UDP com estado incerto (open|filtered): {len(incertas)}")


# ---------------------------------------------------------------------- relatório
def gerar_relatorio(pasta, necessidade=None) -> Path:
    pasta = Path(pasta)
    necessidade = carregar_necessidade() if necessidade is None else necessidade
    resultado = consolidar(pasta)
    linhas = linhas_tabela(resultado, necessidade)
    incertas = linhas_incertas(resultado)

    meta = {}
    meta_arquivo = pasta / "metadata.json"
    if meta_arquivo.exists():
        meta = json.loads(meta_arquivo.read_text(encoding="utf-8"))
    comandos = (pasta / "comando.txt").read_text(encoding="utf-8") if (pasta / "comando.txt").exists() else "_não registrado_"

    partes = [f"# Relatório de varredura: {meta.get('rotulo', pasta.name)}", ""]
    if meta:
        partes += [f"- Data (UTC): {meta.get('data_utc', '')}",
                   f"- Alvo: {meta.get('alvo', '')}",
                   f"- Versão do Nmap: {meta.get('nmap', '')}",
                   f"- Modo privilegiado (SYN/UDP): {'sim' if meta.get('privilegiado') else 'não'}",
                   f"- Autorização: {meta.get('autorizacao', {}).get('data', '')} por "
                   f"{', '.join(meta.get('autorizacao', {}).get('responsaveis', []))}",
                   f"- Redes autorizadas: {', '.join(meta.get('redes_autorizadas', []))}", ""]
    partes += ["## Comandos executados", "```", comandos.strip(), "```", "",
               "## Resumo", resumo_risco(linhas, incertas), "",
               "## Portas, protocolos e serviços", tabela_markdown(linhas), ""]
    if incertas:
        partes += ["## Portas UDP com estado incerto (open|filtered)", NOTA_UDP]
        if len(incertas) >= LIMITE_NOTA_FIREWALL:
            partes.append(NOTA_FIREWALL)
        partes += ["", tabela_incertas_markdown(incertas), ""]
    partes += ["## Análise do SSH", analise_ssh(resultado), ""]
    saida = pasta / "relatorio.md"
    saida.write_text("\n".join(partes), encoding="utf-8")
    return saida


# --------------------------------------------------------------------- comparação
def chaves_abertas(resultado: dict) -> set:
    return {(ip, p["porta"], p["protocolo"]) for ip, d in resultado.items() for p in d["portas"]
            if p["estado"] == "open"}


def chaves_incertas(resultado: dict) -> set:
    return {(ip, p["porta"], p["protocolo"]) for ip, d in resultado.items() for p in d["portas"]
            if p["estado"] == "open|filtered"}


def comparar(pasta_antes, pasta_depois) -> str:
    antes, depois = consolidar(pasta_antes), consolidar(pasta_depois)
    ka, kd = chaves_abertas(antes), chaves_abertas(depois)
    ia, idp = chaves_incertas(antes), chaves_incertas(depois)
    fechadas, mantidas, novas = sorted(ka - kd), sorted(ka & kd), sorted(kd - ka)
    reducao = 0.0 if not ka else 100 * len(fechadas) / len(ka)

    def lista(itens):
        return "\n".join(f"- {ip}:{porta}/{proto}" for ip, porta, proto in itens) or "- (nenhuma)"

    linhas = [
        "# Comparação antes e depois", "",
        f"- Portas abertas confirmadas antes: {len(ka)}",
        f"- Portas abertas confirmadas depois: {len(kd)}",
        f"- Redução da superfície de ataque: {reducao:.0f}%",
        f"- Portas UDP com estado incerto (open|filtered): antes {len(ia)}, depois {len(idp)}", "",
        "## Portas fechadas ou filtradas (abertas antes, não confirmadas depois)", lista(fechadas), "",
        "## Portas mantidas abertas", lista(mantidas), "",
        "## Portas novas abertas", lista(novas), ""]
    if len(idp) >= LIMITE_NOTA_FIREWALL and len(idp) > len(ia):
        linhas += ["## Observação sobre UDP", NOTA_FIREWALL, ""]
    return "\n".join(linhas)


# ------------------------------------------------------------------- varredura
def hash_arquivo(caminho: Path) -> str:
    h = hashlib.sha256()
    h.update(caminho.read_bytes())
    return h.hexdigest()


def escanear(args) -> int:
    escopo = carregar_escopo(args.escopo)
    rede = validar_alvo(args.alvo, escopo["_redes"])
    nmap = localizar_nmap()
    privilegiado = eh_privilegiado()

    pasta = Path(args.saida) / args.rotulo if args.saida else EVID_DIR / args.rotulo
    pasta.mkdir(parents=True, exist_ok=True)
    base = str(pasta / "varredura")
    comandos = []

    def rodar(cmd):
        comandos.append(comando_legivel(cmd, nmap))
        return executar(cmd)

    print(f"Alvo autorizado: {rede} | modo privilegiado: {'sim' if privilegiado else 'não'}")

    if rodar(cmd_descoberta(nmap, args.alvo, base)) != 0:
        print("Falha na descoberta de hosts.")
        return 1
    ativos = hosts_ativos(Path(f"{base}_01_descoberta.xml"))
    if not ativos:
        if not args.assumir_ativo:
            print("Nenhum host respondeu à descoberta. Se o alvo bloqueia ping, use --assumir-ativo.")
            return 1
        ativos = [str(ip) for ip in rede.hosts()] or [str(rede.network_address)]
    print(f"Hosts a varrer: {', '.join(ativos)}")

    if rodar(cmd_tcp(nmap, ativos, base, privilegiado, args.tcp_connect)) != 0:
        print("Falha na varredura TCP.")
        return 1
    portas = portas_abertas_tcp(Path(f"{base}_02_tcp_completo.xml"))
    if portas:
        rodar(cmd_servicos(nmap, ativos, base, portas))
    else:
        print("Nenhuma porta TCP aberta: fase de serviços ignorada.")

    if args.sem_udp:
        print("Fase UDP ignorada (--sem-udp).")
    elif not privilegiado:
        print("Fase UDP ignorada: exige privilégios (root/Administrador).")
    else:
        rodar(cmd_udp(nmap, ativos, base))

    (pasta / "comando.txt").write_text("\n".join(comandos) + "\n", encoding="utf-8")
    meta = {"rotulo": args.rotulo, "alvo": args.alvo, "hosts_varridos": ativos,
            "data_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "nmap": versao_nmap(nmap), "privilegiado": privilegiado,
            "autorizacao": escopo["autorizacao"], "redes_autorizadas": [str(r) for r in escopo["_redes"]]}
    (pasta / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    arquivos = sorted(p for p in pasta.iterdir() if p.suffix in (".xml", ".nmap", ".gnmap", ".txt", ".json"))
    (pasta / "hashes.sha256").write_text(
        "\n".join(f"{hash_arquivo(a)}  {a.name}" for a in arquivos if a.name != "hashes.sha256") + "\n", encoding="utf-8")

    relatorio = gerar_relatorio(pasta, carregar_necessidade(args.necessidade))
    print(f"\nEvidências em: {pasta}\nRelatório: {relatorio}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Varredura controlada de portas e serviços (Nmap)")
    sub = parser.add_subparsers(dest="comando", required=True)

    p_esc = sub.add_parser("escanear", help="executa as quatro fases e salva as evidências")
    p_esc.add_argument("--alvo", required=True, help="IP ou rede CIDR dentro do escopo")
    p_esc.add_argument("--rotulo", default="antes", help="nome da pasta de evidências (ex.: antes, depois)")
    p_esc.add_argument("--escopo", default=str(ESCOPO_PADRAO), help="arquivo de autorização e escopo")
    p_esc.add_argument("--necessidade", default=str(NECESSIDADE_PADRAO), help="arquivo com a necessidade de cada serviço")
    p_esc.add_argument("--saida", help="pasta base das evidências")
    p_esc.add_argument("--tcp-connect", action="store_true", help="usa -sT em vez de -sS")
    p_esc.add_argument("--sem-udp", action="store_true", help="não executa a fase UDP")
    p_esc.add_argument("--assumir-ativo", action="store_true", help="varre mesmo se a descoberta não encontrar o host")

    p_tab = sub.add_parser("tabela", help="gera o relatorio.md a partir dos XMLs de uma pasta")
    p_tab.add_argument("pasta")
    p_tab.add_argument("--necessidade", default=str(NECESSIDADE_PADRAO))

    p_cmp = sub.add_parser("comparar", help="compara duas pastas de varredura")
    p_cmp.add_argument("antes")
    p_cmp.add_argument("depois")
    p_cmp.add_argument("--saida", default=str(EVID_DIR / "comparacao_antes_depois.md"))

    args = parser.parse_args(argv)
    try:
        if args.comando == "escanear":
            return escanear(args)
        if args.comando == "tabela":
            print(f"Relatório gerado: {gerar_relatorio(args.pasta, carregar_necessidade(args.necessidade))}")
            return 0
        texto = comparar(args.antes, args.depois)
        Path(args.saida).parent.mkdir(parents=True, exist_ok=True)
        Path(args.saida).write_text(texto, encoding="utf-8")
        print(texto)
        return 0
    except (ErroEscopo, FileNotFoundError) as e:
        print(f"Erro: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
