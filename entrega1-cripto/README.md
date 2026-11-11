# Entrega 1 — Criptografia assimétrica e confiança

**Disciplina:** Segurança da Informação — UNIT | **Estudante(s):** Wagner Rodrigues, Otávio Henrique, Enzo Leonardo

## 1. Problema e objetivo
Um serviço (A) precisa enviar uma mensagem a outro (B) garantindo que **só B a leia** (sigilo) e que **B tenha certeza de que veio de A e não foi alterada** (autenticidade e integridade). Esta entrega implementa **as duas** opções do enunciado: cifragem híbrida **e** assinatura digital.

## 2. Ambiente e tecnologias
- Python 3.10+ e biblioteca [`cryptography`](https://cryptography.io) (consolidada; nenhum algoritmo próprio).

## 3. Algoritmos, parâmetros e justificativa
| Função | Algoritmo | Parâmetros | Justificativa |
|---|---|---|---|
| Cifrar o conteúdo | AES-GCM | chave 256 bits, nonce 96 bits aleatório, tag 128 bits, AAD = cabeçalho | Cifra autenticada (AEAD): sigilo + integridade; rápida para dados grandes |
| Encapsular a chave AES | RSA-OAEP | RSA-3072, e=65537, SHA-256, MGF1-SHA-256 | OAEP é o preenchimento seguro para cifrar com RSA; 3072 bits ≈ 128 bits de segurança (NIST SP 800-57) |
| Assinar | Ed25519 | chave de 256 bits | Assinatura determinística, rápida, imune a nonce ruim e sem escolhas inseguras de parâmetros |

**Por que híbrida?** RSA só cifra blocos pequenos e é lento. Usa-se o RSA para proteger uma chave simétrica efêmera, e o AES-GCM para o conteúdo.

**Fluxo (encrypt-then-sign):**
1. A gera chave AES-256 e nonce aleatórios (novos a cada mensagem).
2. A cifra a mensagem com AES-GCM.
3. A encapsula a chave AES com a chave pública RSA de B (OAEP).
4. A assina o pacote (nonce, chave encapsulada, texto cifrado, AAD) com sua chave privada Ed25519.
5. B verifica a assinatura **antes** de decifrar; depois decifra com sua chave privada RSA.

## 4. Execução
```bash
pip install cryptography
python entrega1_cripto.py
```
Execute dentro da pasta `entrega1-cripto/`. Gera `./keys/` (PEM; privadas protegidas por senha, `chmod 600`; **não versionada**) e `evidencias/pacote_exemplo.json`.

## 5. Testes e evidências (ver `evidencias/saida_execucao.txt`)
| # | Cenário | Resultado esperado | Obtido |
|---|---|---|---|
| 1 | Pacote íntegro | Mensagem recuperada | ✔ |
| 2 | 1 bit do texto cifrado alterado | Assinatura inválida | ✔ |
| 3 | Atacante altera e re-assina com outra chave | Assinatura inválida | ✔ |
| 4 | Ignorando a assinatura, texto adulterado | Tag GCM inválida (defesa em profundidade) | ✔ |
| 5 | Destinatário errado | Decifragem rejeitada | ✔ |

Para o vídeo de evidência: grave a execução do script e mostre `pacote_exemplo.json` e os arquivos em `keys/`.

## 6. Conceitos exigidos

### Sigilo × autenticidade
- **Sigilo (confidencialidade):** impede que terceiros *leiam* o conteúdo. Obtido aqui com AES-GCM + RSA-OAEP. Quem cifra com a chave **pública** de B garante que só B (dono da privada) decifra.
- **Autenticidade (e integridade/não repúdio):** garante *quem* enviou e que nada foi alterado. Obtida com assinatura digital: A assina com a chave **privada**, qualquer um verifica com a **pública**.
- São propriedades independentes: uma mensagem pode ser sigilosa e forjada (qualquer um pode cifrar com a pública de B), ou autêntica e legível por todos (documento assinado em claro). Por isso o projeto usa as duas.

### Certificados digitais e PKI
Uma chave pública sozinha não prova de quem ela é: um atacante poderia trocá-la pela dele (ataque *man-in-the-middle*). Um **certificado digital X.509** vincula uma identidade (pessoa, domínio, serviço) a uma chave pública e é **assinado por uma Autoridade Certificadora (AC)**. A **PKI** (Infraestrutura de Chaves Públicas) é o conjunto de ACs, cadeias de confiança (raiz → intermediárias → certificado final), políticas, validade, e revogação (CRL/OCSP) que permite confiar nessas ligações. No Brasil, a ICP-Brasil é um exemplo. Neste laboratório as chaves são trocadas manualmente; **em produção, a chave pública de A e a de B seriam distribuídas em certificados validados por uma AC**.

## 7. Gestão de chaves
- Chaves privadas salvas em PEM/PKCS#8 **cifradas por senha** e com permissão restrita; **nunca** versionar `keys/` no Git (use `.gitignore`).
- A senha do script é de laboratório; em produção usar cofre de segredos (Vault, KMS, variáveis de ambiente protegidas).
- Chave AES é efêmera (uma por mensagem) e nunca é gravada.
- Rotação periódica e revogação em caso de comprometimento.

## 8. Riscos, limitações e melhorias
- Sem PKI real: não há validação da identidade dona das chaves públicas.
- Sem proteção contra **replay** (reenvio de pacote válido): adicionar timestamp/ID único assinado.
- Sem *forward secrecy* na cifragem: comprometer a chave RSA de B expõe mensagens antigas interceptadas. Alternativa: ECDH efêmero (X25519) + HKDF.
- Chaves em disco com senha fixa no código (apenas didático).
- RSA-3072 e Ed25519 não são resistentes a computadores quânticos; acompanhar padrões pós-quânticos (ML-KEM / ML-DSA, NIST FIPS 203/204).
- Melhoria: usar certificados X.509 próprios (ex.: gerados com `cryptography.x509` ou OpenSSL) para demonstrar uma mini-PKI.

## 9. Referências consultadas
- Documentação oficial da biblioteca *cryptography*: https://cryptography.io
- NIST. *SP 800-57 Part 1 — Recommendation for Key Management*.
- NIST. *SP 800-38D — Recommendation for GCM and GMAC*.
- RFC 8017 (PKCS #1 v2.2, RSA-OAEP) e RFC 8032 (Ed25519).
- RFC 5280 (certificados X.509 e PKI).
- OWASP Cryptographic Storage Cheat Sheet.
