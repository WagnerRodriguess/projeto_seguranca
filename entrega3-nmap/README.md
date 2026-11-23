# Entrega 3 — Varredura de portas e serviços

**Disciplina:** Segurança da Informação — UNIT
**Estudante(s):** Wagner Rodrigues, Otávio Henrique, Enzo Leonardo

## 1. Problema e objetivo
A equipe precisa avaliar **quais serviços de um ambiente de homologação estão expostos** na rede. O trabalho monta um laboratório isolado, registra a autorização e o escopo, executa uma descoberta controlada com **Nmap**, identifica portas, protocolos e serviços, compara a **necessidade** de cada serviço com a sua **exposição**, analisa o **SSH** e propõe e aplica uma **redução da superfície de ataque**, repetindo a varredura para medir o efeito.

## 2. Ambiente e tecnologias
| Componente | Descrição |
|---|---|
| Alvo | VM Ubuntu Server 22.04/24.04 em rede **host-only** (isolada da internet e da rede da instituição) |
| Scanner | Máquina hospedeira (ou segunda VM) com Nmap 7.9x e Python 3.10+ |
| Rede do laboratório | `192.168.56.0/24` (padrão do host-only), configurável em `escopo.json` |
| Serviços do alvo ("antes") | SSH (22/tcp), FTP (21/tcp), HTTP (80/tcp), MariaDB (3306/tcp), Samba (139/tcp, 445/tcp, 137-138/udp) |
| Bibliotecas | Somente biblioteca padrão do Python (`argparse`, `ipaddress`, `xml.etree`, `subprocess`); sem dependências extras |

## 3. Autorização e escopo
Toda execução exige o arquivo `escopo.json`, que registra os responsáveis, a data e a janela da autorização e as redes permitidas. O script:
- **não executa** se a data ou os responsáveis não estiverem registrados;
- **recusa** alvos fora das redes autorizadas, nomes de host, redes com bits de host e alvos com mais de 256 endereços;
- **recusa** qualquer rede que não seja privada ou de loopback, mesmo que esteja listada no arquivo.

Todos os testes ocorrem em máquinas virtuais próprias. Nenhum alvo público, da universidade ou de terceiros é varrido. A invasão de dispositivo informático é tipificada pela Lei nº 12.737/2012 (art. 154-A do Código Penal), o que reforça a necessidade de autorização expressa.

## 4. Técnicas, comandos e justificativa
`varredura.py escanear` executa quatro fases e registra cada comando em `comando.txt`.

| Fase | Comando | Finalidade |
|---|---|---|
| 1. Descoberta | `nmap -sn -n -oA ..._01_descoberta ALVO` | Identifica hosts ativos sem varrer portas |
| 2. TCP completo | `nmap -sS -Pn -n -p- --open --reason -T3 -oA ..._02_tcp_completo HOSTS` | Todas as 65535 portas TCP; `-sS` (SYN, "meio aberta") exige privilégio e cai para `-sT` sem ele; `--reason` registra por que a porta foi considerada aberta |
| 3. Serviços | `nmap -sV --version-intensity 5 --script=default,ssh-auth-methods,ssh2-enum-algos,ssh-hostkey -Pn -n --reason -p PORTAS_ABERTAS ...` | Identifica produto e versão; scripts da categoria `default` e específicos do SSH (métodos de autenticação, algoritmos, chaves do host) |
| 4. UDP | `nmap -sU --top-ports 20 -Pn -n --open --reason -T3 ...` | As 20 portas UDP mais comuns; UDP é lento e ambíguo (`open\|filtered`) e exige privilégio |

Escolhas de projeto:
- A fase 3 usa apenas as portas encontradas na fase 2, o que torna a identificação mais rápida e precisa.
- `-T3` (perfil normal) evita sobrecarga no alvo e produz resultados mais confiáveis que perfis agressivos.
- Os scripts NSE usados são de descoberta e enumeração de configuração; **não** há força bruta nem exploração.
- Os comandos são montados como listas e executados sem shell, o que impede injeção de comandos pelo argumento `--alvo`.
- Os comandos são registrados em `comando.txt` de forma legível (`nmap` e caminhos relativos), sem expor usuário ou pastas locais.
- Cada execução grava `metadata.json` (data, alvo, versão do Nmap, autorização) e `hashes.sha256` com o SHA-256 dos arquivos, para comprovar a integridade das evidências.

## 5. Necessidade × exposição e classificação de risco
`necessidade.json` declara, para cada porta esperada, se o serviço é **necessário** ao ambiente e por quê. O relatório cruza esse dado com o que foi encontrado:

| Serviço | Necessário? | Justificativa |
|---|---|---|
| SSH 22/tcp | Sim | Administração remota, apenas pela rede de gerência |
| HTTP 80/tcp | Sim | Aplicação web de homologação |
| FTP 21/tcp | Não | Legado, sem criptografia; substituível por SFTP |
| MariaDB 3306/tcp | Não (via rede) | Só a aplicação local precisa acessar o banco |
| Samba 139/445 tcp, 137/138 udp | Não | Compartilhamento de arquivos não é requisito |

O **risco** (Alto, Médio ou Baixo) é uma classificação qualitativa por regras, baseada no tipo de serviço (protocolo sem criptografia, banco de dados e SMB expostos são Alto), na autenticação detectada (SSH com senha é Médio; somente chave é Baixo) e na necessidade (um serviço desnecessário e exposto nunca fica em Baixo). A tabela gerada tem as colunas **Host, Porta, Protocolo, Serviço, Necessário?, Risco e Recomendação**.

## 6. Análise do SSH e boas práticas de autenticação remota
O relatório coleta, por varredura, a versão do OpenSSH, os **métodos de autenticação aceitos**, as **chaves do host** e os **algoritmos** oferecidos, e sinaliza algoritmos obsoletos (por exemplo, `hmac-sha1`, `ssh-rsa`, grupos Diffie-Hellman com SHA-1 e cifras CBC).

Boas práticas aplicadas em `lab/endurecer_alvo.sh`:
- Autenticação por **chave pública**, com `PasswordAuthentication no`; o script só desabilita a senha se o usuário administrador já tiver uma chave em `authorized_keys`, para não perder o acesso à VM.
- `PermitRootLogin no` e `AllowUsers` restrito ao administrador.
- `MaxAuthTries 3`, `LoginGraceTime 30` e `ufw limit` na porta 22, que reduzem a força bruta.
- Acesso ao SSH limitado à rede de gerência pelo firewall.
- Troca de chaves, cifras e MACs modernos (`curve25519-sha256`, `chacha20-poly1305`, `aes-gcm`, `hmac-sha2-*-etm`).
- `X11Forwarding no` e encerramento de sessões ociosas.
- A configuração é validada com `sshd -t` antes de reiniciar o serviço e revertida se for inválida.

## 7. Redução da superfície de ataque
`lab/endurecer_alvo.sh` aplica o plano "depois":
1. Desativa FTP e Samba (serviços não necessários).
2. Restringe o MariaDB a `127.0.0.1`.
3. Endurece o SSH (item anterior).
4. Configura o UFW: nega entrada por padrão, libera SSH somente da rede de gerência e libera HTTP.
5. Oculta versão e assinatura do Apache (`ServerTokens Prod`, `ServerSignature Off`, `TraceEnable Off`).

`varredura.py comparar` mede a redução (portas fechadas, mantidas e novas e o percentual de redução).

## 8. Implementação e execução
```
entrega3-nmap/
├── varredura.py            varredura controlada, tabela e comparação
├── testes_varredura.py     43 testes automatizados
├── escopo.json             autorização e escopo
├── necessidade.json        necessidade de cada serviço
├── lab/provisionar_alvo.sh VM-alvo na configuração "antes"
├── lab/endurecer_alvo.sh   VM-alvo na configuração "depois"
└── evidencias/<rotulo>/    XML, texto, comandos, metadados, hashes e relatório
```
Na VM-alvo (como root):
```bash
sudo bash provisionar_alvo.sh      # linha de base "antes"
sudo bash endurecer_alvo.sh        # redução da superfície ("depois")
```
Na máquina que executa a varredura (com `escopo.json` preenchido):
```bash
python varredura.py escanear --alvo 192.168.56.101 --rotulo antes
python varredura.py escanear --alvo 192.168.56.101 --rotulo depois
python varredura.py comparar evidencias/antes evidencias/depois
python varredura.py tabela evidencias/antes     # regenera o relatório a partir dos XML
python -m unittest -v testes_varredura          # testes automatizados
```
Opções: `--tcp-connect` (usa `-sT`), `--sem-udp`, `--assumir-ativo` (alvos que bloqueiam ping) e `--saida` (pasta das evidências). Para `-sS` e para a fase UDP, execute como root (Linux/macOS) ou como Administrador (Windows).

## 9. Testes e evidências
- `testes_varredura.py`: 43 testes (escopo e autorização, leitura de XML, classificação de risco, análise do SSH, comparação e montagem dos comandos). Os testes usam arquivos XML de exemplo e não executam o Nmap.
- `evidencias/antes/` e `evidencias/depois/`: saída bruta do Nmap (`.xml`, `.nmap`, `.gnmap`), `comando.txt`, `metadata.json`, `hashes.sha256` e `relatorio.md` com a tabela porta/protocolo/serviço/risco/recomendação.
- `evidencias/comparacao_antes_depois.md`: portas fechadas e redução da superfície de ataque.

## 10. Riscos, limitações e melhorias
- A classificação de risco é qualitativa e por regras; não substitui uma análise de vulnerabilidades (CVE) nem pontua severidade como o CVSS. Melhoria: cruzar versões detectadas com bases de vulnerabilidades (NVD) na Entrega 4.
- A fase UDP cobre apenas 20 portas e o estado `open|filtered` é incerto: o relatório não conta essas portas como abertas e as lista em uma seção própria. Quando há um firewall que descarta pacotes (como o UFW com política padrão negada), quase todas as portas UDP ficam nesse estado, o que o relatório sinaliza.
- O script `ssh-hostkey` pode não retornar as chaves do host com versões recentes do OpenSSH (observado com Nmap 7.99 e OpenSSH 10.2); nesse caso o relatório registra "não coletadas". As impressões digitais podem ser obtidas com `ssh-keyscan`.
- A detecção de versão pode ser imprecisa e as varreduras SYN podem ser registradas por IDS/IPS; em ambiente real, a janela deve ser comunicada.
- O laboratório usa o endurecimento por UFW e SSH; um ambiente real também exigiria HTTPS, atualização automática de pacotes e monitoramento de logs.
- Melhoria: adicionar `fail2ban`, autenticação multifator no SSH e varredura recorrente automatizada.

## 11. Referências consultadas
- Nmap Reference Guide: https://nmap.org/book/man.html
- LYON, G. *Nmap Network Scanning*. Nmap Project, 2009.
- SCARFONE, K. et al. *Technical Guide to Information Security Testing and Assessment (NIST SP 800-115)*. NIST, 2008.
- SCARFONE, K.; JANSEN, W.; TRACY, M. *Guide to General Server Security (NIST SP 800-123)*. NIST, 2008.
- OpenBSD. *sshd_config(5)*: https://man.openbsd.org/sshd_config
- OWASP. *Top 10:2021, A05 Security Misconfiguration*.
- BRASIL. Lei nº 12.737, de 30 de novembro de 2012.
