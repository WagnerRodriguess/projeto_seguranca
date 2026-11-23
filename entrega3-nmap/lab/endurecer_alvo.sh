#!/usr/bin/env bash
# Aplica a redução da superfície de ataque na VM-alvo (configuração "depois"):
#   - desativa FTP e Samba (serviços não necessários)
#   - restringe o MariaDB a 127.0.0.1
#   - endurece o SSH (chave pública, sem root, limite de tentativas, criptografia moderna)
#   - firewall UFW: nega entrada por padrão; libera SSH somente da rede de gerência e HTTP
#   - oculta versão e assinatura do Apache
#
# Variáveis opcionais:
#   REDE_ADMIN       rede autorizada a acessar o SSH (padrão: 192.168.56.0/24)
#   USUARIO_ADMIN    usuário que poderá entrar por SSH (padrão: quem executou o sudo)
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Execute com sudo: sudo bash $0" >&2
    exit 1
fi

REDE_ADMIN="${REDE_ADMIN:-192.168.56.0/24}"
USUARIO_ADMIN="${USUARIO_ADMIN:-${SUDO_USER:-}}"
export DEBIAN_FRONTEND=noninteractive

echo "[1/5] Desativando serviços desnecessários (FTP e Samba)"
for servico in vsftpd smbd nmbd; do
    systemctl disable --now "$servico" >/dev/null 2>&1 || true
done

echo "[2/5] Restringindo o MariaDB a 127.0.0.1"
rm -f /etc/mysql/mariadb.conf.d/99-lab-baseline.cnf
cat > /etc/mysql/mariadb.conf.d/99-lab-hardening.cnf <<'CONF'
[mysqld]
bind-address = 127.0.0.1
CONF
systemctl restart mariadb

echo "[3/5] Endurecendo o SSH"
chave_ok=0
if [ -n "$USUARIO_ADMIN" ]; then
    home_admin="$(getent passwd "$USUARIO_ADMIN" | cut -d: -f6)"
    if [ -n "$home_admin" ] && [ -s "$home_admin/.ssh/authorized_keys" ]; then
        chave_ok=1
    fi
fi

rm -f /etc/ssh/sshd_config.d/10-lab-baseline.conf
destino=/etc/ssh/sshd_config.d/10-lab-hardening.conf
{
    echo "PermitRootLogin no"
    echo "PubkeyAuthentication yes"
    echo "MaxAuthTries 3"
    echo "LoginGraceTime 30"
    echo "X11Forwarding no"
    echo "ClientAliveInterval 300"
    echo "ClientAliveCountMax 2"
    echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org"
    echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    if [ "$chave_ok" -eq 1 ]; then
        echo "PasswordAuthentication no"
        echo "AllowUsers $USUARIO_ADMIN"
    fi
} > "$destino"

if sshd -t; then
    systemctl restart ssh
    if [ "$chave_ok" -eq 1 ]; then
        echo "     SSH: autenticação por senha DESABILITADA (somente chave pública)"
    else
        echo "     AVISO: nenhuma chave em ~/.ssh/authorized_keys de '${USUARIO_ADMIN:-?}'." >&2
        echo "     A autenticação por senha foi mantida para evitar perda de acesso à VM." >&2
    fi
else
    echo "Configuração SSH inválida; revertendo." >&2
    rm -f "$destino"
    exit 1
fi

echo "[4/5] Configurando o firewall (UFW)"
apt-get install -y ufw >/dev/null
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw limit from "$REDE_ADMIN" to any port 22 proto tcp
ufw allow 80/tcp
ufw --force enable

echo "[5/5] Ocultando versão e assinatura do Apache"
cat > /etc/apache2/conf-available/lab-hardening.conf <<'CONF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off
CONF
a2enconf lab-hardening >/dev/null
systemctl reload apache2

echo
echo "Portas em escuta:"
ss -tulpn
echo
ufw status verbose
