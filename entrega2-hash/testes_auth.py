"""
Testes automatizados da Entrega 2.
Execução (dentro da pasta entrega2-hash): python -m unittest -v testes_auth
"""
import unittest
from datetime import timedelta

from argon2 import PasswordHasher, Type

import entrega2_auth as auth

SENHA = "senha forte exemplo"


class TestesAutenticacao(unittest.TestCase):
    def setUp(self):
        self.con = auth.conectar(":memory:")

    def tearDown(self):
        self.con.close()

    def hash_de(self, usuario):
        return self.con.execute(
            "SELECT senha_hash FROM usuarios WHERE usuario = ?", (usuario,)
        ).fetchone()[0]

    def test_01_armazena_hash_argon2id_e_nao_a_senha(self):
        auth.registrar(self.con, "ana", SENHA)
        armazenado = self.hash_de("ana")
        self.assertTrue(armazenado.startswith("$argon2id$"))
        self.assertNotIn(SENHA, armazenado)
        dump = " ".join(str(c) for linha in self.con.execute("SELECT * FROM usuarios") for c in linha)
        self.assertNotIn(SENHA, dump)

    def test_02_parametros_do_hash(self):
        auth.registrar(self.con, "ana", SENHA)
        d = auth.detalhar_hash(self.hash_de("ana"))
        self.assertEqual(d["memoria_KiB"], str(auth.MEMORY_COST_KIB))
        self.assertEqual(d["iteracoes"], str(auth.TIME_COST))
        self.assertEqual(d["paralelismo"], str(auth.PARALLELISM))

    def test_03_mesma_senha_gera_hashes_diferentes_por_causa_do_salt(self):
        auth.registrar(self.con, "ana", SENHA)
        auth.registrar(self.con, "bruno", SENHA)
        self.assertNotEqual(self.hash_de("ana"), self.hash_de("bruno"))
        self.assertNotEqual(
            auth.detalhar_hash(self.hash_de("ana"))["salt"],
            auth.detalhar_hash(self.hash_de("bruno"))["salt"],
        )

    def test_04_login_correto(self):
        auth.registrar(self.con, "ana", SENHA)
        ok, _ = auth.login(self.con, "ana", SENHA)
        self.assertTrue(ok)

    def test_05_login_com_senha_incorreta(self):
        auth.registrar(self.con, "ana", SENHA)
        ok, msg = auth.login(self.con, "ana", "senha errada 123456")
        self.assertFalse(ok)
        self.assertEqual(msg, auth.MSG_CREDENCIAIS)

    def test_06_usuario_inexistente_tem_a_mesma_mensagem(self):
        auth.registrar(self.con, "ana", SENHA)
        _, msg_errada = auth.login(self.con, "ana", "senha errada 123456")
        _, msg_inexistente = auth.login(self.con, "fantasma", SENHA)
        self.assertEqual(msg_errada, msg_inexistente)

    def test_07_usuario_nao_diferencia_maiusculas(self):
        auth.registrar(self.con, "Ana", SENHA)
        self.assertTrue(auth.login(self.con, "ANA", SENHA)[0])

    def test_08_rejeita_senha_curta_e_longa(self):
        with self.assertRaises(ValueError):
            auth.registrar(self.con, "ana", "curta123")
        with self.assertRaises(ValueError):
            auth.registrar(self.con, "ana", "a" * (auth.SENHA_MAX + 1))

    def test_09_rejeita_senha_igual_ao_usuario(self):
        with self.assertRaisesRegex(ValueError, "igual"):
            auth.registrar(self.con, "usuario-comprido-123", "usuario-comprido-123")

    def test_10_rejeita_usuario_invalido_e_duplicado(self):
        with self.assertRaises(ValueError):
            auth.registrar(self.con, "a b", SENHA)
        auth.registrar(self.con, "ana", SENHA)
        with self.assertRaises(ValueError):
            auth.registrar(self.con, "ana", SENHA)

    def test_11_sql_injection_nao_autentica_e_nao_quebra(self):
        auth.registrar(self.con, "ana", SENHA)
        ok, _ = auth.login(self.con, "' OR '1'='1' --", "qualquer senha 123")
        self.assertFalse(ok)
        ok, _ = auth.login(self.con, "ana", "' OR '1'='1")
        self.assertFalse(ok)
        total = self.con.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
        self.assertEqual(total, 1)

    def test_12_bloqueio_apos_falhas_consecutivas(self):
        auth.registrar(self.con, "ana", SENHA)
        for _ in range(auth.MAX_TENTATIVAS):
            auth.login(self.con, "ana", "senha errada 123456")
        ok, msg = auth.login(self.con, "ana", SENHA)
        self.assertFalse(ok)
        self.assertEqual(msg, auth.MSG_BLOQUEADA)

    def test_13_bloqueio_expira(self):
        auth.registrar(self.con, "ana", SENHA)
        for _ in range(auth.MAX_TENTATIVAS):
            auth.login(self.con, "ana", "senha errada 123456")
        passado = (auth.agora() - timedelta(minutes=1)).isoformat()
        self.con.execute("UPDATE usuarios SET bloqueado_ate = ? WHERE usuario = 'ana'", (passado,))
        self.con.commit()
        self.assertTrue(auth.login(self.con, "ana", SENHA)[0])

    def test_14_login_correto_zera_contador_de_falhas(self):
        auth.registrar(self.con, "ana", SENHA)
        for _ in range(auth.MAX_TENTATIVAS - 1):
            auth.login(self.con, "ana", "senha errada 123456")
        self.assertTrue(auth.login(self.con, "ana", SENHA)[0])
        falhas = self.con.execute("SELECT tentativas_falhas FROM usuarios").fetchone()[0]
        self.assertEqual(falhas, 0)

    def test_15_rehash_atualiza_parametros_antigos(self):
        antigo = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1, type=Type.ID)
        self.con.execute(
            "INSERT INTO usuarios (usuario, senha_hash, criado_em) VALUES (?, ?, ?)",
            ("carla", antigo.hash(SENHA), auth.agora().isoformat()),
        )
        self.con.commit()
        self.assertEqual(auth.detalhar_hash(self.hash_de("carla"))["memoria_KiB"], "8192")
        self.assertTrue(auth.login(self.con, "carla", SENHA)[0])
        self.assertEqual(
            auth.detalhar_hash(self.hash_de("carla"))["memoria_KiB"], str(auth.MEMORY_COST_KIB)
        )

    def test_17_rejeita_senha_da_blocklist(self):
        with self.assertRaises(ValueError):
            auth.registrar(self.con, "ana", "PasswordPassword")

    def test_18_unicode_normalizado_antes_do_hash(self):
        composta = "sen\u00e1forte exemplo"
        decomposta = "sena\u0301forte exemplo"
        auth.registrar(self.con, "ana", composta)
        self.assertTrue(auth.login(self.con, "ana", decomposta)[0])

    def test_16_hash_corrompido_nao_autentica(self):
        auth.registrar(self.con, "ana", SENHA)
        self.con.execute("UPDATE usuarios SET senha_hash = 'lixo' WHERE usuario = 'ana'")
        self.con.commit()
        self.assertFalse(auth.login(self.con, "ana", SENHA)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
