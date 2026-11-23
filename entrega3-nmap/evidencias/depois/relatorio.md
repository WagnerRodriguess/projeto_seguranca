# Relatório de varredura: depois

- Data (UTC): 2026-11-22T05:44:29+00:00
- Alvo: 192.168.56.101
- Versão do Nmap: Nmap version 7.993 ( https://nmap.org )
- Modo privilegiado (SYN/UDP): sim
- Autorização: 2026-11-22 por Enzo Leonardo Reis Santana, Otávio Henrique Santos Mercena, Wagner Rodrigues Chagas
- Redes autorizadas: 192.168.56.0/24

## Comandos executados
```
nmap -sn -n -oA evidencias\depois\varredura_01_descoberta 192.168.56.101
nmap -sS -Pn -n -p- --open --reason -T3 -oA evidencias\depois\varredura_02_tcp_completo 192.168.56.101
nmap -sV --version-intensity 5 --script=default,ssh-auth-methods,ssh2-enum-algos,ssh-hostkey -Pn -n --reason -p 22,80 -oA evidencias\depois\varredura_03_servicos 192.168.56.101
nmap -sU --top-ports 20 -Pn -n --open --reason -T3 -oA evidencias\depois\varredura_04_udp 192.168.56.101
```

## Resumo
- Portas abertas (confirmadas): 2
- Risco Alto: 0, Médio: 1, Baixo: 1
- Expostas e não necessárias: 0
- Portas UDP com estado incerto (open|filtered): 20

## Portas, protocolos e serviços
| Host | Porta | Protocolo | Serviço | Necessário? | Risco | Recomendação |
|---|---|---|---|---|---|---|
| 192.168.56.101 | 22 | TCP | ssh - OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 | Sim | Baixo | Manter; restringir origem e limitar tentativas |
| 192.168.56.101 | 80 | TCP | http - Apache httpd 2.4.66 | Sim | Médio | Servir por HTTPS, redirecionar HTTP, ocultar versão e manter atualizado |

## Portas UDP com estado incerto (open|filtered)
O UDP não tem handshake: quando a porta não responde, o Nmap não consegue distinguir uma porta aberta de uma porta filtrada (estado `open|filtered`). Estas portas **não estão confirmadas como abertas**.
A grande quantidade de portas `open|filtered` sem resposta é o comportamento típico de um firewall que descarta pacotes (política DROP): sem a resposta "porta fechada", todas as portas ficam inconclusivas. Isso não indica que os serviços estejam ativos.

| Host | Porta | Protocolo | Serviço provável |
|---|---|---|---|
| 192.168.56.101 | 53 | UDP | domain |
| 192.168.56.101 | 67 | UDP | dhcps |
| 192.168.56.101 | 68 | UDP | dhcpc |
| 192.168.56.101 | 69 | UDP | tftp |
| 192.168.56.101 | 123 | UDP | ntp |
| 192.168.56.101 | 135 | UDP | msrpc |
| 192.168.56.101 | 137 | UDP | netbios-ns |
| 192.168.56.101 | 138 | UDP | netbios-dgm |
| 192.168.56.101 | 139 | UDP | netbios-ssn |
| 192.168.56.101 | 161 | UDP | snmp |
| 192.168.56.101 | 162 | UDP | snmptrap |
| 192.168.56.101 | 445 | UDP | microsoft-ds |
| 192.168.56.101 | 500 | UDP | isakmp |
| 192.168.56.101 | 514 | UDP | syslog |
| 192.168.56.101 | 520 | UDP | route |
| 192.168.56.101 | 631 | UDP | ipp |
| 192.168.56.101 | 1434 | UDP | ms-sql-m |
| 192.168.56.101 | 1900 | UDP | upnp |
| 192.168.56.101 | 4500 | UDP | nat-t-ike |
| 192.168.56.101 | 49152 | UDP | desconhecido |

## Análise do SSH
### SSH em 192.168.56.101:22
- Versão: OpenSSH 10.2p1 Ubuntu 2ubuntu3.8
- Métodos de autenticação aceitos: publickey
- Chaves do host: não coletadas (o script ssh-hostkey não retornou chaves)
- Algoritmos: não coletado
