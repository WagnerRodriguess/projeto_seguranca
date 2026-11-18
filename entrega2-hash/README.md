# Entrega 2 — Hash e autenticação segura

**Disciplina:** Segurança da Informação — UNIT
**Estudante(s):** Wagner Rodrigues, Otávio Henrique, Enzo Leonardo

## 1. Problema e objetivo
Uma aplicação precisa cadastrar usuários **sem armazenar senhas em texto puro**. A solução implementa cadastro e login com **Argon2id**, armazenamento do hash (com salt embutido) em SQLite, comparação segura feita pela biblioteca e controles complementares contra ataques comuns.

## 2. Ambiente e tecnologias
- Python 3.10+
- [`argon2-cffi`](https://argon2-cffi.readthedocs.io) (Argon2id), sem algoritmo próprio
- `sqlite3` e `unittest` (biblioteca padrão)
- `hashlib` (biblioteca padrão), usado **somente** na demonstração que compara SHA-256 com Argon2id

## 3. Algoritmo, parâmetros e justificativa
| Item | Valor | Justificativa |
|---|---|---|
| Algoritmo | **Argon2id** | Vencedor do Password Hashing Competition; combina resistência a ataques por GPU (memory-hard) e a canais laterais; recomendado pela OWASP e padronizado na RFC 9106 |
| Memória (`m`) | 65536 KiB (64 MiB) | Acima do mínimo recomendado pela OWASP; encarece ataques com GPU |
| Iterações (`t`) | 3 | Custo de tempo |
| Paralelismo (`p`) | 4 | Lanes do Argon2 |
| Salt | 16 bytes aleatórios, único por usuário | Impede que senhas iguais gerem hashes iguais e inutiliza tabelas pré-calculadas |
| Saída | 32 bytes | Tamanho padrão do hash |

O hash é guardado no formato PHC, que já carrega algoritmo, versão, parâmetros e salt:
```
$argon2id$v=19$m=65536,t=3,p=4$<salt em base64>$<hash em base64>
```
Se o custo mudar no futuro, `check_needs_rehash()` detecta hashes antigos e o sistema os atualiza no próximo login bem-sucedido.

### Por que SHA-256 isolado não é adequado para senhas
- **É rápido por projeto:** milhões de palpites por segundo em uma CPU e bilhões em GPU. Para senhas, isso é uma desvantagem.
- **Sem salt, senhas iguais geram hashes iguais:** quem vê o banco descobre quais usuários repetem a senha, e tabelas pré-calculadas (rainbow tables) funcionam.
- **Sem custo ajustável:** não há como aumentar o trabalho por tentativa com o passar dos anos.
- A demonstração (passo 6 da execução) mede os dois: o Argon2id fica centenas de milhares de vezes mais lento para quem tenta adivinhar.

### Comparação segura
O login usa `PasswordHasher.verify()`, que recalcula o hash com o salt e os parâmetros armazenados e faz a comparação dentro da biblioteca (rotina em C do Argon2, em tempo constante). **Não** se compara hashes com `==` no código da aplicação.

## 4. Implementação
Arquivos:
- `entrega2_auth.py`: aplicação (cadastro, login, demonstração e modo interativo)
- `testes_auth.py`: 18 testes automatizados
- `evidencias/`: saída da execução, saída dos testes e o registro protegido do banco

Controles implementados:
- Validação: usuário de 3 a 32 caracteres (`a-z A-Z 0-9 _ . -`); senha de **15 a 128** caracteres, sem regras de composição, com lista de bloqueio de senhas comuns (alinhado ao NIST SP 800-63B-4)
- Normalização Unicode (NFC) da senha antes do hash
- Consultas SQL **parametrizadas** (proteção contra SQL injection)
- Mensagem única para qualquer falha: "Usuário ou senha inválidos" (evita enumeração de usuários)
- Para usuário inexistente, executa uma verificação "falsa" para equalizar o tempo de resposta
- Bloqueio temporário de 5 minutos após 5 falhas consecutivas
- Rehash automático quando os parâmetros ficam desatualizados

## 5. Execução
A partir da raiz do repositório:
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd entrega2-hash
python entrega2_auth.py                # demonstração completa
python entrega2_auth.py --interativo   # cadastro e login manuais (asteriscos; pergunta se mostra a senha)
python -m unittest -v testes_auth      # testes automatizados
```
No modo interativo, antes de cada cadastro e de cada login o programa pergunta **"Mostrar a senha enquanto digita? (s/N)"**. O padrão (Enter ou "n") exibe um **asterisco por tecla** e aceita Backspace. Respondendo "s", a senha aparece na tela. O NIST SP 800-63B-4 recomenda oferecer a opção de exibir a senha para reduzir erros de digitação.

O banco fica em `dados/` (não versionado). A demonstração usa `dados/demo.db`, recriado a cada execução, e **somente senhas fictícias**.

## 6. Testes e evidências
| Evidência | Arquivo |
|---|---|
| Execução da demonstração (cadastro, login correto/incorreto, bloqueio, rehash, SHA-256 × Argon2id) | `evidencias/saida_execucao.txt` |
| 18 testes automatizados | `evidencias/saida_testes.txt` |
| Registro protegido no banco (hash e salt, sem senha em texto puro) | `evidencias/banco_registro_protegido.txt` |
| Modo interativo: asteriscos, Backspace, pergunta "mostrar senha" | `evidencias/saida_modo_interativo.txt` |

Pontos demonstrados: senha ausente do arquivo do banco; duas contas com a mesma senha e hashes/salts diferentes; login correto aceito e incorreto recusado; entrada tipo SQL injection tratada como texto comum; bloqueio após 5 falhas; atualização dos parâmetros no login.

## 7. Riscos, limitações e melhorias
- Sem MFA. Melhoria: TOTP ou passkeys.
- Sem *pepper* (chave secreta guardada fora do banco). Melhoria: aplicar HMAC com chave em cofre/HSM antes do Argon2id.
- A lista de bloqueio é pequena. Melhoria: usar bases de senhas vazadas (por exemplo, a API Pwned Passwords).
- O bloqueio por conta permite que alguém trave contas alheias de propósito. Melhoria: limitação por IP, atraso progressivo e CAPTCHA.
- Aplicação de linha de comando: em um sistema web é obrigatório usar HTTPS, cookies de sessão seguros e proteção contra CSRF.
- A senha existe em memória Python durante a verificação e não pode ser apagada com garantia.
- Não há fluxo de recuperação de senha nem registro de auditoria dos logins.

## 8. Referências consultadas
- Documentação oficial do argon2-cffi: https://argon2-cffi.readthedocs.io
- BIRYUKOV, A. et al. *RFC 9106: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*. IETF, 2021.
- TEMOSHOK, D. et al. *NIST SP 800-63B-4: Digital Identity Guidelines, Authentication and Authenticator Management*. NIST, 2025.
- OWASP. *Password Storage Cheat Sheet*.
- OWASP. *Application Security Verification Standard (ASVS)*.
