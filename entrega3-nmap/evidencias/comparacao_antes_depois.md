# Comparação antes e depois

- Portas abertas confirmadas antes: 7
- Portas abertas confirmadas depois: 2
- Redução da superfície de ataque: 71%
- Portas UDP com estado incerto (open|filtered): antes 2, depois 20

## Portas fechadas ou filtradas (abertas antes, não confirmadas depois)
- 192.168.56.101:21/tcp
- 192.168.56.101:137/udp
- 192.168.56.101:139/tcp
- 192.168.56.101:445/tcp
- 192.168.56.101:3306/tcp

## Portas mantidas abertas
- 192.168.56.101:22/tcp
- 192.168.56.101:80/tcp

## Portas novas abertas
- (nenhuma)

## Observação sobre UDP
A grande quantidade de portas `open|filtered` sem resposta é o comportamento típico de um firewall que descarta pacotes (política DROP): sem a resposta "porta fechada", todas as portas ficam inconclusivas. Isso não indica que os serviços estejam ativos.
