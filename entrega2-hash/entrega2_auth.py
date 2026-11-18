"""
Cenário: uma aplicação precisa cadastrar usuários sem armazenar senhas em texto puro.

Solução:
  - Hash de senha com Argon2id (biblioteca argon2-cffi), com salt aleatório por usuário
  - Armazenamento em SQLite com consultas parametrizadas
  - Login com comparação segura feita pela biblioteca (verify)
  - Mensagens genéricas, tempo equalizado para usuário inexistente e bloqueio temporário

Instalação: pip install -r requirements.txt
Demonstração:  python entrega2_auth.py
Modo interativo (asteriscos; pergunta se deseja ver a senha): python entrega2_auth.py --interativo
"""
import getpass
import hashlib
import os
import re
import sqlite3
import sys
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "dados"
DB_PATH = DATA_DIR / "usuarios.db"
DB_DEMO = DATA_DIR / "demo.db"
EVID_DIR = BASE_DIR / "evidencias"

TIME_COST = 3
MEMORY_COST_KIB = 65536
PARALLELISM = 4
HASH_LEN = 32
SALT_LEN = 16

SENHA_MIN = 15
SENHA_MAX = 128
MAX_TENTATIVAS = 5
BLOQUEIO_MINUTOS = 5

MSG_CREDENCIAIS = "Usuário ou senha inválidos"
MSG_BLOQUEADA = "Conta temporariamente bloqueada. Tente novamente mais tarde"

USUARIO_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")

BLOCKLIST = {
    "123456789012345",
    "1234567890123456",
    "abcdefghijklmno",
    "iloveyouiloveyou",
    "minhasenha12345",
    "password1234567",
    "passwordpassword",
    "qwertyuiopasdfghjkl",
    "senha123456789",
    "senhasenhasenha",
}

ph = PasswordHasher(
    time_cost=TIME_COST,
    memory_cost=MEMORY_COST_KIB,
    parallelism=PARALLELISM,
    hash_len=HASH_LEN,
    salt_len=SALT_LEN,
    type=Type.ID,
)

HASH_FALSO = ph.hash("hash-falso-para-igualar-o-tempo-de-resposta")


# ------------------------------------------------------------------- banco de dados
def agora() -> datetime:
    return datetime.now(timezone.utc)


def conectar(caminho=DB_PATH) -> sqlite3.Connection:
    if str(caminho) != ":memory:":
        Path(caminho).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(caminho)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            tentativas_falhas INTEGER NOT NULL DEFAULT 0,
            bloqueado_ate TEXT,
            criado_em TEXT NOT NULL
        )
        """
    )
    con.commit()
    return con


# ------------------------------------------------------------------------ validação
def normalizar(usuario: str) -> str:
    return usuario.strip().lower()


def preparar(senha: str) -> str:
    return unicodedata.normalize("NFC", senha)


def validar_usuario(usuario: str):
    if not USUARIO_RE.fullmatch(usuario.strip()):
        raise ValueError("Usuário inválido: use 3 a 32 caracteres (letras, números, _ . -)")


def validar_senha(senha: str, usuario: str):
    if len(senha) < SENHA_MIN:
        raise ValueError(f"Senha muito curta: mínimo de {SENHA_MIN} caracteres")
    if len(senha) > SENHA_MAX:
        raise ValueError(f"Senha muito longa: máximo de {SENHA_MAX} caracteres")
    if senha.lower() == usuario.strip().lower():
        raise ValueError("A senha não pode ser igual ao nome de usuário")
    if senha.lower() in BLOCKLIST:
        raise ValueError("Senha muito comum: escolha outra")


# --------------------------------------------------------------------------- cadastro
def registrar(con: sqlite3.Connection, usuario: str, senha: str):
    validar_usuario(usuario)
    validar_senha(senha, usuario)
    senha_hash = ph.hash(preparar(senha))
    try:
        con.execute(
            "INSERT INTO usuarios (usuario, senha_hash, criado_em) VALUES (?, ?, ?)",
            (normalizar(usuario), senha_hash, agora().isoformat()),
        )
        con.commit()
    except sqlite3.IntegrityError:
        raise ValueError("Usuário já cadastrado")


# ------------------------------------------------------------------------------ login
def verificar_falso(senha: str):
    try:
        ph.verify(HASH_FALSO, preparar(senha))
    except VerifyMismatchError:
        pass


def registrar_falha(con: sqlite3.Connection, id_usuario: int, falhas_atuais: int):
    falhas = falhas_atuais + 1
    if falhas >= MAX_TENTATIVAS:
        ate = (agora() + timedelta(minutes=BLOQUEIO_MINUTOS)).isoformat()
        con.execute(
            "UPDATE usuarios SET tentativas_falhas = 0, bloqueado_ate = ? WHERE id = ?",
            (ate, id_usuario),
        )
    else:
        con.execute(
            "UPDATE usuarios SET tentativas_falhas = ? WHERE id = ?", (falhas, id_usuario)
        )
    con.commit()


def login(con: sqlite3.Connection, usuario: str, senha: str):
    linha = con.execute(
        "SELECT id, senha_hash, tentativas_falhas, bloqueado_ate FROM usuarios WHERE usuario = ?",
        (normalizar(usuario),),
    ).fetchone()

    if linha is None:
        verificar_falso(senha)
        return False, MSG_CREDENCIAIS

    id_usuario, senha_hash, falhas, bloqueado_ate = linha

    if bloqueado_ate and datetime.fromisoformat(bloqueado_ate) > agora():
        verificar_falso(senha)
        return False, MSG_BLOQUEADA

    try:
        ph.verify(senha_hash, preparar(senha))
    except (VerifyMismatchError, InvalidHashError):
        registrar_falha(con, id_usuario, falhas)
        return False, MSG_CREDENCIAIS

    novo_hash = ph.hash(preparar(senha)) if ph.check_needs_rehash(senha_hash) else senha_hash
    con.execute(
        "UPDATE usuarios SET senha_hash = ?, tentativas_falhas = 0, bloqueado_ate = NULL WHERE id = ?",
        (novo_hash, id_usuario),
    )
    con.commit()
    return True, "Login realizado com sucesso"


def detalhar_hash(codificado: str) -> dict:
    _, algoritmo, versao, params, salt, hash_ = codificado.split("$")
    p = dict(item.split("=") for item in params.split(","))
    return {
        "algoritmo": algoritmo,
        "versao": versao,
        "memoria_KiB": p["m"],
        "iteracoes": p["t"],
        "paralelismo": p["p"],
        "salt": salt,
        "hash": hash_,
    }


def tabela_banco(con: sqlite3.Connection) -> str:
    linhas = []
    for usuario, senha_hash in con.execute("SELECT usuario, senha_hash FROM usuarios ORDER BY id"):
        d = detalhar_hash(senha_hash)
        linhas.append(f"usuario: {usuario}")
        linhas.append(f"  senha_hash (completo): {senha_hash}")
        linhas.append(
            f"  algoritmo={d['algoritmo']} {d['versao']} m={d['memoria_KiB']} KiB "
            f"t={d['iteracoes']} p={d['paralelismo']}"
        )
        linhas.append(f"  salt (base64): {d['salt']}")
        linhas.append(f"  hash (base64): {d['hash']}")
        linhas.append("")
    return "\n".join(linhas).rstrip()


def senha_aparece_no_arquivo(caminho: Path, senha: str) -> bool:
    return senha.encode() in Path(caminho).read_bytes()


def titulo(texto: str):
    print(f"\n--- {texto} ---")


def comparar_sha256_argon2id():
    senha = "senha ficticia exemplo"

    h1 = hashlib.sha256(senha.encode()).hexdigest()
    h2 = hashlib.sha256(senha.encode()).hexdigest()
    print("SHA-256 sem salt (dois usuários, mesma senha):")
    print(f"  usuário 1: {h1}")
    print(f"  usuário 2: {h2}")
    print(f"  hashes iguais? {h1 == h2}  -> quem vê um, descobre todos os que usam a mesma senha")

    a1, a2 = ph.hash(senha), ph.hash(senha)
    print("Argon2id com salt (dois usuários, mesma senha):")
    print(f"  usuário 1: {a1[:60]}...")
    print(f"  usuário 2: {a2[:60]}...")
    print(f"  hashes iguais? {a1 == a2}")

    n = 200_000
    t0 = time.perf_counter()
    for i in range(n):
        hashlib.sha256(b"senha%d" % i).digest()
    taxa_sha = n / (time.perf_counter() - t0)

    m = 5
    t0 = time.perf_counter()
    for i in range(m):
        ph.hash(f"senha{i}")
    dur = (time.perf_counter() - t0) / m
    taxa_arg = 1 / dur

    print("Custo para testar palpites de senha (1 núcleo de CPU):")
    print(f"  SHA-256 : ~{taxa_sha:,.0f} palpites/segundo")
    print(f"  Argon2id: ~{taxa_arg:,.1f} palpites/segundo ({dur * 1000:.0f} ms por hash)")
    print(f"  Argon2id é ~{taxa_sha / taxa_arg:,.0f}x mais lento para quem tenta adivinhar")


# --------------------------------------------------------------------- demonstração
def demo():
    print("=== ENTREGA 2: Hash e autenticação segura ===")
    DATA_DIR.mkdir(exist_ok=True)
    EVID_DIR.mkdir(exist_ok=True)
    if DB_DEMO.exists():
        DB_DEMO.unlink()
    con = conectar(DB_DEMO)

    senha_ana = "senha forte exemplo"
    senha_bruno = "senha forte exemplo"

    titulo("1) Cadastro (senhas fictícias)")
    registrar(con, "ana", senha_ana)
    print("Usuário 'ana' cadastrado.")
    registrar(con, "bruno", senha_bruno)
    print("Usuário 'bruno' cadastrado com a MESMA senha de 'ana'.")
    for u, s in (("a", "curta"), ("ana", "outra senha longa 123"), ("x y", "senha bem longa 123")):
        try:
            registrar(con, u, s)
        except ValueError as e:
            print(f"Rejeitado ({u!r}): {e}")

    titulo("2) Registro protegido no banco (nenhuma senha em texto puro)")
    texto_tabela = tabela_banco(con)
    print(texto_tabela)
    (EVID_DIR / "banco_registro_protegido.txt").write_text(texto_tabela + "\n", encoding="utf-8")
    print(f"\nSenha em texto puro aparece no arquivo do banco? {senha_aparece_no_arquivo(DB_DEMO, senha_ana)}")
    print("Hashes de 'ana' e 'bruno' iguais? "
          f"{con.execute('SELECT COUNT(DISTINCT senha_hash) FROM usuarios').fetchone()[0] == 1} (salts diferentes)")

    titulo("3) Login correto e incorreto")
    print("ana + senha correta  ->", login(con, "ana", senha_ana))
    print("ana + senha errada   ->", login(con, "ana", "senha errada 123456"))
    print("usuário inexistente  ->", login(con, "fantasma", "qualquer senha 123"))
    print("Entrada tipo SQL injection ->", login(con, "' OR '1'='1' --", "qualquer senha123"))

    titulo(f"4) Bloqueio temporário após {MAX_TENTATIVAS} falhas seguidas")
    for i in range(1, MAX_TENTATIVAS + 1):
        print(f"tentativa errada {i} em 'bruno' ->", login(con, "bruno", "tentativa incorreta 1"))
    print("senha CORRETA durante o bloqueio ->", login(con, "bruno", senha_bruno))

    titulo("5) Atualização automática de parâmetros (rehash)")
    antigo = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1, type=Type.ID)
    hash_antigo = antigo.hash("senha exemplo forte")
    con.execute(
        "INSERT INTO usuarios (usuario, senha_hash, criado_em) VALUES (?, ?, ?)",
        ("carla", hash_antigo, agora().isoformat()),
    )
    con.commit()
    d0 = detalhar_hash(hash_antigo)
    print(f"Antes do login : m={d0['memoria_KiB']} KiB, t={d0['iteracoes']}, p={d0['paralelismo']}")
    print("login de 'carla' ->", login(con, "carla", "senha exemplo forte"))
    novo = con.execute("SELECT senha_hash FROM usuarios WHERE usuario = 'carla'").fetchone()[0]
    d1 = detalhar_hash(novo)
    print(f"Depois do login: m={d1['memoria_KiB']} KiB, t={d1['iteracoes']}, p={d1['paralelismo']}")

    titulo("6) Por que SHA-256 isolado não é adequado para senhas")
    comparar_sha256_argon2id()

    con.close()
    print("\nDemonstração concluída.")


# ------------------------------------------------------------------ modo interativo
def ler_senha_asteriscos(prompt: str = "Senha: ") -> str:
    if not sys.stdin.isatty():
        return getpass.getpass(prompt)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    chars = []
    if os.name == "nt":
        import msvcrt

        while True:
            c = msvcrt.getwch()
            if c in ("\r", "\n"):
                break
            if c == "\x03":
                raise KeyboardInterrupt
            if c in ("\x00", "\xe0"):
                msvcrt.getwch()
            elif c == "\b":
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
            else:
                chars.append(c)
                sys.stdout.write("*")
            sys.stdout.flush()
    else:
        import termios
        import tty

        fd = sys.stdin.fileno()
        antigo = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                c = sys.stdin.read(1)
                if c in ("\r", "\n", ""):
                    break
                if c in ("\x7f", "\b"):
                    if chars:
                        chars.pop()
                        sys.stdout.write("\b \b")
                elif c == "\x1b":
                    c2 = sys.stdin.read(1)
                    if c2 in ("[", "O"):
                        while True:
                            c3 = sys.stdin.read(1)
                            if c3 == "" or "@" <= c3 <= "~":
                                break
                elif c.isprintable():
                    chars.append(c)
                    sys.stdout.write("*")
                sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, antigo)
    sys.stdout.write("\n")
    return "".join(chars)


def perguntar_mostrar_senha() -> bool:
    resposta = input("Mostrar a senha enquanto digita? (s/N): ").strip().lower()
    return resposta in ("s", "sim")


def ler_senha(visivel: bool) -> str:
    if visivel:
        return input("Senha: ")
    return ler_senha_asteriscos("Senha: ")


def interativo():
    con = conectar(DB_PATH)
    print("=== Cadastro e login (Argon2id) ===")
    while True:
        print("\n1) Cadastrar   2) Login   0) Sair")
        opcao = input("Opção: ").strip()
        if opcao == "0":
            break
        if opcao not in ("1", "2"):
            continue
        visivel = perguntar_mostrar_senha()
        if visivel:
            print("Atenção: a senha ficará visível na tela. Use apenas senhas fictícias.")
        usuario = input("Usuário: ")
        senha = ler_senha(visivel)
        if opcao == "1":
            try:
                registrar(con, usuario, senha)
                print("Cadastro realizado.")
            except ValueError as e:
                print(f"Erro: {e}")
        else:
            print(login(con, usuario, senha)[1])
    con.close()


if __name__ == "__main__":
    if "--interativo" in sys.argv:
        interativo()
    else:
        demo()
