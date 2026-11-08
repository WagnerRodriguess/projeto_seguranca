# Projeto Integrador — Segurança Aplicada ao Desenvolvimento

Disciplina: Segurança da Informação — Sistemas de Informação/ADS — UNIT
Docente: Ana Carla do Nascimento Santos

**Estudante(s):** Wagner Rodrigues, Otávio Henrique, Robert Costa

## Entregas

| # | Tema | Pasta | Status |
|---|------|-------|--------|
| 1 | Criptografia assimétrica e confiança | [`entrega1-cripto`](entrega1-cripto/) | ✅ Concluída |
| 2 | Hash e autenticação segura | [`entrega2-hash`](entrega2-hash/) | ⏳ Pendente |
| 3 | Varredura de portas e serviços | [`entrega3-nmap`](entrega3-nmap/) | ⏳ Pendente |
| 4 | Auditoria e correção de vulnerabilidades | [`entrega4-auditoria`](entrega4-auditoria/) | ⏳ Pendente |

A documentação técnica em formato ABNT de cada entrega fica em [`docs/`](docs/).

## Como reproduzir

```bash
git clone <url-do-repositorio>
cd projeto-seguranca
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd entrega1-cripto
python entrega1_cripto.py
```

## Aviso ético
Todos os testes são realizados somente em aplicações, máquinas e redes próprias ou expressamente autorizadas. Não são usados dados reais nem credenciais de terceiros. Chaves privadas **não** são versionadas.
