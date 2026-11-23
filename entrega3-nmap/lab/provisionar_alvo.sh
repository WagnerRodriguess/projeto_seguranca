#!/usr/bin/env bash
# Provisiona a VM-alvo do laboratório (Ubuntu Server 22.04 ou 24.04) com a configuração
# de linha de base ("antes"): serviços expostos, alguns deliberadamente desnecessários.
# Executar somente em máquina virtual própria, em rede host-only, sem acesso à internet pública.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Execute com sudo: sudo bash $0" >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y openssh-server apache2 vsftpd mariadb-server samba iproute2

# SSH: linha de base permissiva (senha e login de root habilitados)
install -d /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/10-lab-baseline.conf <<'CONF'
PasswordAuthentication yes
PermitRootLogin yes
X11Forwarding yes
CONF

# MariaDB: escuta em todas as interfaces (exposição desnecessária)
cat > /etc/mysql/mariadb.conf.d/99-lab-baseline.cnf <<'CONF'
[mysqld]
bind-address = 0.0.0.0
CONF

# Samba: habilita o NetBIOS (nmbd), que em versões recentes vem desativado por padrão
sed -i '/^[[:space:]]*disable netbios[[:space:]]*=/d' /etc/samba/smb.conf
sed -i '/^\[global\]/a\   disable netbios = no' /etc/samba/smb.conf

# Habilita e inicia os serviços
for servico in ssh apache2 vsftpd mariadb smbd nmbd; do
    systemctl enable "$servico" >/dev/null 2>&1 || true
    systemctl restart "$servico"
done

echo
echo "Endereços IP da VM:"
ip -brief address show
echo
echo "Portas em escuta (TCP e UDP):"
ss -tulpn
