# Relatório de varredura: antes

- Data (UTC): 2026-11-22T05:04:30+00:00
- Alvo: 192.168.56.101
- Versão do Nmap: Nmap version 7.993 ( https://nmap.org )
- Modo privilegiado (SYN/UDP): sim
- Autorização: 2026-11-22 por Enzo Leonardo Reis Santana, Otávio Henrique Santos Mercena, Wagner Rodrigues Chagas
- Redes autorizadas: 192.168.56.0/24

## Comandos executados
```
C:\Program Files (x86)\Nmap\nmap.EXE -sn -n -oA C:\Users\Wagner\Desktop\etc\programacao\projeto_seguranca\entrega3-nmap\evidencias\antes\varredura_01_descoberta 192.168.56.101
C:\Program Files (x86)\Nmap\nmap.EXE -sS -Pn -n -p- --open --reason -T3 -oA C:\Users\Wagner\Desktop\etc\programacao\projeto_seguranca\entrega3-nmap\evidencias\antes\varredura_02_tcp_completo 192.168.56.101
C:\Program Files (x86)\Nmap\nmap.EXE -sV --version-intensity 5 --script=default,ssh-auth-methods,ssh2-enum-algos -Pn -n --reason -p 21,22,80,139,445,3306 -oA C:\Users\Wagner\Desktop\etc\programacao\projeto_seguranca\entrega3-nmap\evidencias\antes\varredura_03_servicos 192.168.56.101
C:\Program Files (x86)\Nmap\nmap.EXE -sU --top-ports 20 -Pn -n --open --reason -T3 -oA C:\Users\Wagner\Desktop\etc\programacao\projeto_seguranca\entrega3-nmap\evidencias\antes\varredura_04_udp 192.168.56.101
```

## Resumo
- Portas abertas (confirmadas): 7
- Risco Alto: 4, Médio: 3, Baixo: 0
- Expostas e não necessárias: 5
- Portas UDP com estado incerto (open|filtered): 2

## Portas, protocolos e serviços
| Host | Porta | Protocolo | Serviço | Necessário? | Risco | Recomendação |
|---|---|---|---|---|---|---|
| 192.168.56.101 | 21 | TCP | ftp - vsftpd 3.0.5 | Não | Alto | Desativar/bloquear: serviço não necessário. Desativar; transferir arquivos por SFTP (sobre SSH) ou FTPS |
| 192.168.56.101 | 22 | TCP | ssh - OpenSSH 10.2p1 Ubuntu 2ubuntu3.8 | Sim | Médio | Desabilitar senha e usar chave pública; negar root; restringir origem e limitar tentativas |
| 192.168.56.101 | 80 | TCP | http - Apache httpd 2.4.66 | Sim | Médio | Servir por HTTPS, redirecionar HTTP, ocultar versão e manter atualizado |
| 192.168.56.101 | 139 | TCP | netbios-ssn - Samba smbd 4 | Não | Alto | Desativar/bloquear: serviço não necessário. Desativar ou bloquear no firewall |
| 192.168.56.101 | 445 | TCP | netbios-ssn - Samba smbd 4 | Não | Alto | Desativar/bloquear: serviço não necessário. Desativar ou bloquear no firewall |
| 192.168.56.101 | 3306 | TCP | mysql - MariaDB 10.3.23 or earlier | Não | Alto | Desativar/bloquear: serviço não necessário. Vincular a 127.0.0.1 ou a uma rede interna e filtrar no firewall |
| 192.168.56.101 | 137 | UDP | netbios-ns | Não | Médio | Desativar/bloquear: serviço não necessário. Desativar ou bloquear no firewall |

## Portas UDP com estado incerto (open|filtered)
O UDP não tem handshake: quando a porta não responde, o Nmap não consegue distinguir uma porta aberta de uma porta filtrada (estado `open|filtered`). Estas portas **não estão confirmadas como abertas**.

| Host | Porta | Protocolo | Serviço provável |
|---|---|---|---|
| 192.168.56.101 | 68 | UDP | dhcpc |
| 192.168.56.101 | 138 | UDP | netbios-dgm |

## Análise do SSH
### SSH em 192.168.56.101:22
- Versão: OpenSSH 10.2p1 Ubuntu 2ubuntu3.8
- Métodos de autenticação aceitos: publickey, password
  - Achado: autenticação por senha habilitada
- Chaves do host: não coletadas (o script ssh-hostkey não retornou chaves)
- Algoritmos fracos oferecidos: hmac-sha1, umac-64@openssh.com
