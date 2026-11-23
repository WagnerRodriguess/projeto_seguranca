"""
Testes automatizados da Entrega 3.
Execução (dentro da pasta entrega3-nmap): python -m unittest -v testes_varredura

Os testes não executam o Nmap: usam arquivos XML de exemplo (fixtures) no formato gerado pelo Nmap.
"""
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path

import varredura as v

CABECALHO = '<?xml version="1.0"?><nmaprun scanner="nmap" args="teste">'
RODAPE = "</nmaprun>"


def host(ip, portas, estado="up"):
    return (f'<host><status state="{estado}"/><address addr="{ip}" addrtype="ipv4"/>'
            f"<ports>{portas}</ports></host>")


def porta(num, proto, estado, nome, produto="", versao="", scripts="", tunel=""):
    t = f' tunnel="{tunel}"' if tunel else ""
    return (f'<port protocol="{proto}" portid="{num}"><state state="{estado}" reason="syn-ack"/>'
            f'<service name="{nome}" product="{produto}" version="{versao}"{t}/>{scripts}</port>')


SSH_COM_SENHA = (
    '<script id="ssh-auth-methods" output="x"><table key="Supported authentication methods">'
    "<elem>publickey</elem><elem>password</elem></table></script>"
    '<script id="ssh2-enum-algos" output="x">'
    '<table key="kex_algorithms"><elem>curve25519-sha256</elem><elem>diffie-hellman-group14-sha1</elem></table>'
    '<table key="mac_algorithms"><elem>hmac-sha2-256</elem><elem>hmac-sha1</elem></table></script>'
    '<script id="ssh-hostkey" output="x"><table><elem key="bits">1024</elem><elem key="type">ssh-rsa</elem></table>'
    '<table><elem key="bits">256</elem><elem key="type">ssh-ed25519</elem></table></script>'
)
SSH_SO_CHAVE = (
    '<script id="ssh-auth-methods" output="x"><table key="Supported authentication methods">'
    "<elem>publickey</elem></table></script>"
)

XML_ANTES = CABECALHO + host("192.168.56.101", "".join([
    porta(21, "tcp", "open", "ftp", "vsftpd", "3.0.5"),
    porta(22, "tcp", "open", "ssh", "OpenSSH", "9.6p1", SSH_COM_SENHA),
    porta(80, "tcp", "open", "http", "Apache httpd", "2.4.58"),
    porta(3306, "tcp", "open", "mysql", "MariaDB", "10.11"),
    porta(445, "tcp", "open", "microsoft-ds"),
    porta(23, "tcp", "closed", "telnet"),
])) + RODAPE

XML_UDP = CABECALHO + host("192.168.56.101", porta(137, "udp", "open", "netbios-ns")
                           + porta(138, "udp", "open|filtered", "netbios-dgm")) + RODAPE

XML_UDP_FIREWALL = CABECALHO + host("192.168.56.101", "".join(
    porta(n, "udp", "open|filtered", "desconhecido") for n in range(1000, 1015))) + RODAPE

XML_DEPOIS = CABECALHO + host("192.168.56.101", "".join([
    porta(22, "tcp", "open", "ssh", "OpenSSH", "9.6p1", SSH_SO_CHAVE),
    porta(80, "tcp", "open", "http", "Apache httpd", "2.4"),
])) + RODAPE

NECESSIDADE = {
    "22/tcp": {"necessario": True, "justificativa": "admin"},
    "80/tcp": {"necessario": True, "justificativa": "web"},
    "21/tcp": {"necessario": False, "justificativa": "legado"},
    "3306/tcp": {"necessario": False, "justificativa": "só local"},
}


def gravar(pasta: Path, nome: str, conteudo: str) -> Path:
    pasta.mkdir(parents=True, exist_ok=True)
    caminho = pasta / nome
    caminho.write_text(conteudo, encoding="utf-8")
    return caminho


class TestesEscopo(unittest.TestCase):
    def setUp(self):
        self.redes = [ipaddress.ip_network("192.168.56.0/24")]

    def escopo(self, **alteracoes):
        dados = {"autorizacao": {"responsaveis": ["Aluno"], "data": "2026-11-18"},
                 "redes_autorizadas": ["192.168.56.0/24"]}
        dados.update(alteracoes)
        tmp = tempfile.mkdtemp()
        return gravar(Path(tmp), "escopo.json", json.dumps(dados))

    def test_01_aceita_host_dentro_do_escopo(self):
        self.assertEqual(str(v.validar_alvo("192.168.56.101", self.redes)), "192.168.56.101/32")

    def test_02_aceita_a_rede_do_escopo(self):
        self.assertEqual(str(v.validar_alvo("192.168.56.0/24", self.redes)), "192.168.56.0/24")

    def test_03_recusa_host_fora_do_escopo(self):
        with self.assertRaisesRegex(v.ErroEscopo, "fora do escopo"):
            v.validar_alvo("192.168.57.10", self.redes)

    def test_04_recusa_ip_publico(self):
        with self.assertRaisesRegex(v.ErroEscopo, "fora do escopo"):
            v.validar_alvo("8.8.8.8", self.redes)

    def test_05_recusa_nome_de_host(self):
        with self.assertRaisesRegex(v.ErroEscopo, "Alvo inválido"):
            v.validar_alvo("exemplo.com", self.redes)

    def test_06_recusa_rede_com_bits_de_host(self):
        with self.assertRaisesRegex(v.ErroEscopo, "Alvo inválido"):
            v.validar_alvo("192.168.56.101/24", self.redes)

    def test_07_recusa_alvo_maior_que_o_limite(self):
        grande = [ipaddress.ip_network("10.0.0.0/8")]
        with self.assertRaisesRegex(v.ErroEscopo, "muito grande"):
            v.validar_alvo("10.0.0.0/16", grande)

    def test_08_carrega_escopo_valido(self):
        dados = v.carregar_escopo(self.escopo())
        self.assertEqual([str(r) for r in dados["_redes"]], ["192.168.56.0/24"])

    def test_09_recusa_escopo_sem_data(self):
        caminho = self.escopo(autorizacao={"responsaveis": ["Aluno"], "data": "[PREENCHER AAAA-MM-DD]"})
        with self.assertRaisesRegex(v.ErroEscopo, "data da autorização"):
            v.carregar_escopo(caminho)

    def test_10_recusa_escopo_sem_responsaveis(self):
        caminho = self.escopo(autorizacao={"responsaveis": [], "data": "2026-11-18"})
        with self.assertRaisesRegex(v.ErroEscopo, "responsáveis"):
            v.carregar_escopo(caminho)

    def test_11_recusa_escopo_com_rede_publica(self):
        with self.assertRaisesRegex(v.ErroEscopo, "não é privada"):
            v.carregar_escopo(self.escopo(redes_autorizadas=["8.8.8.0/24"]))

    def test_12_recusa_escopo_sem_redes(self):
        with self.assertRaisesRegex(v.ErroEscopo, "redes_autorizadas"):
            v.carregar_escopo(self.escopo(redes_autorizadas=[]))

    def test_13_arquivo_de_escopo_inexistente(self):
        with self.assertRaisesRegex(v.ErroEscopo, "não encontrado"):
            v.carregar_escopo(Path(tempfile.mkdtemp()) / "nao_existe.json")

    def test_14_cli_retorna_erro_para_alvo_fora_do_escopo(self):
        caminho = self.escopo()
        codigo = v.main(["escanear", "--alvo", "10.1.1.1", "--escopo", str(caminho)])
        self.assertEqual(codigo, 2)


class TestesAnalise(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.antes = self.tmp / "antes"
        self.depois = self.tmp / "depois"
        gravar(self.antes, "varredura_03_servicos.xml", XML_ANTES)
        gravar(self.antes, "varredura_04_udp.xml", XML_UDP)
        gravar(self.depois, "varredura_03_servicos.xml", XML_DEPOIS)

    def portas(self, resultado, ip="192.168.56.101"):
        return {(p["porta"], p["protocolo"]): p for p in resultado[ip]["portas"]}

    def test_15_ler_xml_extrai_portas_e_servicos(self):
        resultado = v.consolidar(self.antes)
        p = self.portas(resultado)
        self.assertEqual(p[(21, "tcp")]["servico"], "ftp")
        self.assertEqual(p[(21, "tcp")]["produto"], "vsftpd")
        self.assertEqual(p[(3306, "tcp")]["servico"], "mysql")
        self.assertIn((137, "udp"), p)

    def test_16_consolida_tcp_e_udp(self):
        resultado = v.consolidar(self.antes)
        protocolos = {x["protocolo"] for x in resultado["192.168.56.101"]["portas"]}
        self.assertEqual(protocolos, {"tcp", "udp"})

    def test_17_pasta_sem_xml(self):
        with self.assertRaises(FileNotFoundError):
            v.consolidar(self.tmp / "vazia")

    def test_18_hosts_ativos_e_portas_tcp_abertas(self):
        caminho = self.antes / "varredura_03_servicos.xml"
        self.assertEqual(v.hosts_ativos(caminho), ["192.168.56.101"])
        self.assertEqual(v.portas_abertas_tcp(caminho), {21, 22, 80, 3306, 445})

    def test_19_metodos_ssh_com_senha(self):
        p = self.portas(v.consolidar(self.antes))[(22, "tcp")]
        self.assertEqual(v.metodos_ssh(p), ["publickey", "password"])

    def test_20_algoritmos_fracos_do_ssh(self):
        p = self.portas(v.consolidar(self.antes))[(22, "tcp")]
        algoritmos = {a for lista in v.algoritmos_ssh(p).values() for a in lista}
        fracos = algoritmos & v.SSH_ALGORITMOS_FRACOS
        self.assertEqual(fracos, {"diffie-hellman-group14-sha1", "hmac-sha1"})

    def test_21_chaves_do_host(self):
        p = self.portas(v.consolidar(self.antes))[(22, "tcp")]
        self.assertIn(("ssh-rsa", "1024"), v.chaves_ssh(p))

    def test_22_ftp_e_risco_alto(self):
        p = self.portas(v.consolidar(self.antes))[(21, "tcp")]
        c = v.classificar(p, NECESSIDADE)
        self.assertEqual(c["risco"], "Alto")
        self.assertIn("Desativar", c["recomendacao"])
        self.assertIs(c["necessario"], False)

    def test_23_ssh_com_senha_recomenda_chave(self):
        p = self.portas(v.consolidar(self.antes))[(22, "tcp")]
        c = v.classificar(p, NECESSIDADE)
        self.assertEqual(c["risco"], "Médio")
        self.assertIn("Desabilitar senha", c["recomendacao"])

    def test_24_ssh_somente_chave_e_risco_baixo(self):
        p = self.portas(v.consolidar(self.depois))[(22, "tcp")]
        self.assertEqual(v.classificar(p, NECESSIDADE)["risco"], "Baixo")

    def test_25_servico_desnecessario_nunca_fica_em_risco_baixo(self):
        p = {"porta": 123, "protocolo": "udp", "estado": "open", "servico": "ntp", "produto": "", "versao": "",
             "extra": "", "tunel": "", "scripts": {}}
        base = v.classificar(p, {})
        self.assertEqual(base["risco"], "Baixo")
        self.assertEqual(v.classificar(p, {"123/udp": {"necessario": False}})["risco"], "Médio")

    def test_26_http_sobre_tls_e_tratado_como_https(self):
        p = {"porta": 8443, "protocolo": "tcp", "estado": "open", "servico": "http", "produto": "", "versao": "",
             "extra": "", "tunel": "ssl", "scripts": {}}
        self.assertEqual(v.classificar(p, {})["risco"], "Baixo")

    def test_27_servico_desconhecido_exige_revisao(self):
        p = {"porta": 9999, "protocolo": "tcp", "estado": "open", "servico": "desconhecido", "produto": "",
             "versao": "", "extra": "", "tunel": "", "scripts": {}}
        c = v.classificar(p, {})
        self.assertEqual(c["risco"], "Médio")
        self.assertIsNone(c["necessario"])

    def test_28_tabela_lista_somente_portas_abertas(self):
        linhas = v.linhas_tabela(v.consolidar(self.antes), NECESSIDADE)
        portas = {(l["porta"], l["protocolo"]) for l in linhas}
        self.assertNotIn((23, "TCP"), portas)
        self.assertIn((137, "UDP"), portas)
        self.assertNotIn((138, "UDP"), portas)
        self.assertEqual(len(linhas), 6)

    def test_29_tabela_markdown_tem_as_colunas_exigidas(self):
        texto = v.tabela_markdown(v.linhas_tabela(v.consolidar(self.antes), NECESSIDADE))
        cabecalho = texto.splitlines()[0]
        for coluna in ("Porta", "Protocolo", "Serviço", "Risco", "Recomendação"):
            self.assertIn(coluna, cabecalho)

    def test_30_resumo_conta_expostas_e_desnecessarias(self):
        linhas = v.linhas_tabela(v.consolidar(self.antes), NECESSIDADE)
        resumo = v.resumo_risco(linhas)
        self.assertIn("Portas abertas (confirmadas): 6", resumo)
        self.assertIn("não necessárias: 2", resumo)

    def test_31_analise_ssh_aponta_achados(self):
        texto = v.analise_ssh(v.consolidar(self.antes))
        self.assertIn("autenticação por senha habilitada", texto)
        self.assertIn("chave de host fraca", texto)
        self.assertIn("hmac-sha1", texto)

    def test_43_analise_ssh_informa_quando_as_chaves_do_host_nao_foram_coletadas(self):
        texto = v.analise_ssh(v.consolidar(self.depois))
        self.assertIn("Chaves do host: não coletadas", texto)

    def test_32_comparacao_antes_e_depois(self):
        texto = v.comparar(self.antes, self.depois)
        self.assertIn("Portas abertas confirmadas antes: 6", texto)
        self.assertIn("Portas abertas confirmadas depois: 2", texto)
        self.assertIn("Redução da superfície de ataque: 67%", texto)
        self.assertIn("192.168.56.101:21/tcp", texto)
        self.assertIn("## Portas novas abertas\n- (nenhuma)", texto)

    def test_40_udp_incerto_fica_fora_da_tabela_e_e_listado_a_parte(self):
        resultado = v.consolidar(self.antes)
        incertas = v.linhas_incertas(resultado)
        self.assertEqual([(i["porta"], i["protocolo"]) for i in incertas], [(138, "UDP")])
        conteudo = v.gerar_relatorio(self.antes, NECESSIDADE).read_text(encoding="utf-8")
        self.assertIn("## Portas UDP com estado incerto", conteudo)
        self.assertIn("estado incerto (open|filtered): 1", conteudo)

    def test_41_muitas_portas_udp_incertas_geram_nota_sobre_firewall(self):
        gravar(self.depois, "varredura_04_udp.xml", XML_UDP_FIREWALL)
        conteudo = v.gerar_relatorio(self.depois, NECESSIDADE).read_text(encoding="utf-8")
        self.assertIn("política DROP", conteudo)
        texto = v.comparar(self.antes, self.depois)
        self.assertIn("Observação sobre UDP", texto)
        self.assertIn("Redução da superfície de ataque: 67%", texto)
        self.assertIn("depois 15", texto)

    def test_42_poucas_portas_incertas_nao_geram_nota_de_firewall(self):
        conteudo = v.gerar_relatorio(self.antes, NECESSIDADE).read_text(encoding="utf-8")
        self.assertNotIn("política DROP", conteudo)
        self.assertNotIn("Observação sobre UDP", v.comparar(self.antes, self.depois))

    def test_33_relatorio_e_gerado(self):
        saida = v.gerar_relatorio(self.antes, NECESSIDADE)
        conteudo = saida.read_text(encoding="utf-8")
        self.assertIn("## Portas, protocolos e serviços", conteudo)
        self.assertIn("## Análise do SSH", conteudo)


class TestesComandos(unittest.TestCase):
    def test_34_usa_syn_quando_privilegiado(self):
        cmd = v.cmd_tcp("nmap", ["10.0.0.1"], "base", privilegiado=True, tcp_connect=False)
        self.assertIn("-sS", cmd)
        self.assertIn("-p-", cmd)

    def test_35_usa_connect_sem_privilegio_ou_quando_pedido(self):
        self.assertIn("-sT", v.cmd_tcp("nmap", ["10.0.0.1"], "base", privilegiado=False, tcp_connect=False))
        self.assertIn("-sT", v.cmd_tcp("nmap", ["10.0.0.1"], "base", privilegiado=True, tcp_connect=True))

    def test_36_comandos_sao_listas_sem_shell(self):
        for cmd in (v.cmd_descoberta("nmap", "10.0.0.1", "b"), v.cmd_servicos("nmap", ["10.0.0.1"], "b", {22, 80}),
                    v.cmd_udp("nmap", ["10.0.0.1"], "b")):
            self.assertIsInstance(cmd, list)
            self.assertTrue(all(isinstance(x, str) for x in cmd))

    def test_37_fase_de_servicos_usa_apenas_as_portas_abertas(self):
        cmd = v.cmd_servicos("nmap", ["10.0.0.1"], "b", {80, 22})
        self.assertEqual(cmd[cmd.index("-p") + 1], "22,80")
        self.assertIn("-sV", cmd)

    def test_38_fase_de_servicos_coleta_metodos_algoritmos_e_chaves_do_ssh(self):
        script = next(x for x in v.cmd_servicos("nmap", ["10.0.0.1"], "b", {22}) if x.startswith("--script="))
        for nome in ("ssh-auth-methods", "ssh2-enum-algos", "ssh-hostkey"):
            self.assertIn(nome, script)

    def test_39_comando_registrado_nao_expoe_caminhos_locais(self):
        nmap = r"C:\Program Files (x86)\Nmap\nmap.EXE"
        base = str(v.BASE_DIR / "evidencias" / "antes" / "varredura")
        texto = v.comando_legivel(v.cmd_descoberta(nmap, "192.168.56.101", base), nmap)
        self.assertTrue(texto.startswith("nmap -sn"))
        self.assertNotIn("Program Files", texto)
        self.assertNotIn(str(v.BASE_DIR), texto)
        self.assertIn("192.168.56.101", texto)


if __name__ == "__main__":
    unittest.main(verbosity=2)
