"""
Cenário: o Serviço A envia uma mensagem ao Serviço B protegendo:
  - SIGILO:        cifragem híbrida (AES-256-GCM + RSA-OAEP/SHA-256)
  - AUTENTICIDADE: assinatura digital Ed25519 sobre o pacote cifrado

Usa apenas a biblioteca consolidada `cryptography`.
Instalação: pip install cryptography
Execução:   python entrega1_cripto.py
"""
import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_BITS = 3072         
AES_KEY_BITS = 256    
NONCE_BYTES = 12        
KEYS_DIR = Path("keys")         
EVID_DIR = Path("evidencias")


# ---------------------------------------------------------------- utilitários
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


# ------------------------------------------------------------ gestão de chaves
def gerar_chaves():
    """Gera: par RSA do destinatário (B) e par Ed25519 do remetente (A)."""
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    return rsa_priv, ed_priv


def salvar_chaves(rsa_priv, ed_priv, senha: bytes):
    """Persiste as chaves privadas CIFRADAS por senha (PEM/PKCS8) e as públicas em claro."""
    KEYS_DIR.mkdir(exist_ok=True)
    enc = serialization.BestAvailableEncryption(senha)
    pk8 = serialization.PrivateFormat.PKCS8
    pem = serialization.Encoding.PEM
    pub = serialization.PublicFormat.SubjectPublicKeyInfo

    (KEYS_DIR / "destinatario_rsa_priv.pem").write_bytes(rsa_priv.private_bytes(pem, pk8, enc))
    (KEYS_DIR / "destinatario_rsa_pub.pem").write_bytes(rsa_priv.public_key().public_bytes(pem, pub))
    (KEYS_DIR / "remetente_ed25519_priv.pem").write_bytes(ed_priv.private_bytes(pem, pk8, enc))
    (KEYS_DIR / "remetente_ed25519_pub.pem").write_bytes(ed_priv.public_key().public_bytes(pem, pub))
    for f in KEYS_DIR.glob("*_priv.pem"):
        os.chmod(f, 0o600)  

# ------------------------------------------------------------------ remetente
def proteger(mensagem: bytes, rsa_pub, ed_priv) -> dict:
    """Cifra (sigilo) e assina (autenticidade/integridade) a mensagem."""
    # 1) Chave simétrica efêmera, nova a cada mensagem
    chave_aes = AESGCM.generate_key(bit_length=AES_KEY_BITS)
    nonce = os.urandom(NONCE_BYTES) 

    # 2) AES-GCM cifra o conteúdo (e autentica via tag de 128 bits embutida)
    cabecalho = b"entrega1-v1"
    texto_cifrado = AESGCM(chave_aes).encrypt(nonce, mensagem, cabecalho)

    # 3) RSA-OAEP encapsula a chave AES para o destinatário
    chave_encapsulada = rsa_pub.encrypt(chave_aes, oaep())

    pacote = {
        "aad": b64e(cabecalho),
        "nonce": b64e(nonce),
        "chave_encapsulada": b64e(chave_encapsulada),
        "texto_cifrado": b64e(texto_cifrado),
    }

    # 4) Ed25519 assina a serialização canônica do pacote
    pacote["assinatura"] = b64e(ed_priv.sign(serializar(pacote)))
    return pacote


def serializar(pacote: dict) -> bytes:
    """Serialização determinística (exclui o campo 'assinatura')."""
    corpo = {k: v for k, v in pacote.items() if k != "assinatura"}
    return json.dumps(corpo, sort_keys=True, separators=(",", ":")).encode()


# --------------------------------------------------------------- destinatário
def receber(pacote: dict, rsa_priv, ed_pub) -> bytes:
    """Verifica a assinatura PRIMEIRO; só então decifra."""
    try:
        ed_pub.verify(b64d(pacote["assinatura"]), serializar(pacote))
    except InvalidSignature:
        raise ValueError("FALHA: assinatura inválida (origem/integridade não confirmadas)")

    try:
        chave_aes = rsa_priv.decrypt(b64d(pacote["chave_encapsulada"]), oaep())
        return AESGCM(chave_aes).decrypt(
            b64d(pacote["nonce"]), b64d(pacote["texto_cifrado"]), b64d(pacote["aad"])
        )
    except (InvalidTag, ValueError):
        raise ValueError("FALHA: decifragem rejeitada (dados adulterados ou chave errada)")


# ------------------------------------------------------------------ demonstração
def adulterar_texto_cifrado(pacote: dict) -> dict:
    p = dict(pacote)
    bruto = bytearray(b64d(p["texto_cifrado"]))
    bruto[0] ^= 0x01
    p["texto_cifrado"] = b64e(bytes(bruto))
    return p


def main():
    print("=== ENTREGA 1: Criptografia assimétrica e confiança ===\n")

    # Geração e armazenamento das chaves
    rsa_priv, ed_priv = gerar_chaves()
    salvar_chaves(rsa_priv, ed_priv, senha=b"senha-de-laboratorio-trocar")
    print(f"[1] Chaves geradas (RSA-{RSA_BITS} e Ed25519) e salvas em ./{KEYS_DIR}/")

    mensagem = "Transferir R$ 1.000,00 para a conta 1234-5".encode()
    print(f"[2] Mensagem original: {mensagem.decode()}")

    pacote = proteger(mensagem, rsa_priv.public_key(), ed_priv)
    print(f"[3] Pacote protegido (texto cifrado, base64): {pacote['texto_cifrado'][:40]}...")
    EVID_DIR.mkdir(exist_ok=True)
    (EVID_DIR / "pacote_exemplo.json").write_text(json.dumps(pacote, indent=2))

    # Teste 1: sucesso
    print("\n--- TESTE 1: pacote íntegro ---")
    recebida = receber(pacote, rsa_priv, ed_priv.public_key())
    print(f"Sucesso. Mensagem recuperada: {recebida.decode()}")
    assert recebida == mensagem

    # Teste 2: texto cifrado adulterado
    print("\n--- TESTE 2: 1 bit do texto cifrado adulterado ---")
    try:
        receber(adulterar_texto_cifrado(pacote), rsa_priv, ed_priv.public_key())
    except ValueError as e:
        print(e)

    # Teste 3: adulteração + nova assinatura por atacante (chave diferente)
    print("\n--- TESTE 3: atacante re-assina com a própria chave ---")
    atacante = ed25519.Ed25519PrivateKey.generate()
    forjado = adulterar_texto_cifrado(pacote)
    forjado["assinatura"] = b64e(atacante.sign(serializar(forjado)))
    try:
        receber(forjado, rsa_priv, ed_priv.public_key())
    except ValueError as e:
        print(e)

    # Teste 4: o que a assinatura sozinha impede e o que o AES-GCM sozinho impede
    print("\n--- TESTE 4: assinatura ignorada: o AES-GCM também protege ---")
    p = adulterar_texto_cifrado(pacote)
    try:
        chave = rsa_priv.decrypt(b64d(p["chave_encapsulada"]), oaep())
        AESGCM(chave).decrypt(b64d(p["nonce"]), b64d(p["texto_cifrado"]), b64d(p["aad"]))
    except InvalidTag:
        print("FALHA: tag GCM inválida (o próprio AES-GCM detecta a adulteração)")

    # Teste 5: chave privada errada (sigilo)
    print("\n--- TESTE 5: destinatário errado tenta decifrar ---")
    outra_rsa, _ = gerar_chaves()
    try:
        receber(pacote, outra_rsa, ed_priv.public_key())
    except ValueError as e:
        print(e)

    print("\nTodos os testes concluídos como esperado.")


if __name__ == "__main__":
    main()
