#!/bin/bash

ipset create -exist diswall-wl hash:net comment
ipset create -exist diswall-bl hash:ip hashsize 32768 maxelem 1000000 timeout 86400

# Получаем список IP с которых входили пользователи от команды last:
IP_last=$(last --ip root | grep pts/ | awk '{ print $3 }' | grep -v ":" | sort -V | uniq)

# Получаем список IP с которых входили пользователи из /var/log/auth.log:
IP_auth=$(egrep "Accepted (publickey|password) for " /var/log/auth.log | sed -E 's/^.*from ([0-9]+\.[0-9]+.[0-9]+.[0-9]+).*$/\1/' | sort -V | uniq)

# Объединяем массивы адресов и оставляем уникальные значения:
IP=$(echo ${IP_last[@]} ${IP_auth[@]} | sed 's/ /\n/g' | sort -V | uniq)

# Удаляем адреса 0.0.0.0 и 127.0.0.1:
IP_unwanted=("0.0.0.0" "127.0.0.1")
for del_ip in ${IP_unwanted[@]}; do
        IP=(${IP[@]/$del_ip})
done

# Получаем список процессов слушающих порты на не локальных интерфейсах:
local_processes=$(ss -4nlptuH | (grep -v 'users'|sed 's/\s*$/ users:(("kernel",pid=0,fd=0))/g' ; ss -4nlptuH|grep 'users:') | sed -E 's/^([^ ]+)\s+.+\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:.*\s+users:\(\("([^"]+)".*$/\2:\3:\1:\4/' | sort -V | uniq)

echo Собранные адреса:
echo ${IP[@]}

echo Собранные процессы:
echo ${local_processes[@]}

echo Обнуляем текущие правила iptables:
echo iptables -P INPUT ACCEPT
iptables -P INPUT ACCEPT
echo iptables -F INPUT
iptables -F INPUT

echo Создаём новые правила:
# Стандартное начало:
echo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
echo iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
echo iptables -A INPUT -m set --match-set diswall-wl src -j ACCEPT
iptables -A INPUT -m set --match-set diswall-wl src -j ACCEPT
echo iptables -A INPUT -m set --match-set diswall-bl src -j DROP
iptables -A INPUT -m set --match-set diswall-bl src -j DROP

# Разрешаем доступ обнаруженным IP на обнаруженные службы:
for l_p in ${local_processes[@]}; do
        #socket=(`echo $p | tr ":" " "`)
        read addr port proto proc <<<$(echo $l_p | tr ":" " ")
        if [ $port -eq 80 ] || [ $port -eq 443 ] || [ $port -eq 53 ] || [ $port -eq 4244 ] || [ $port -eq 7743 ] || [ $port -eq 8843 ]; then
                echo iptables -A INPUT -p $proto --dport $port -m comment --comment "$proc" -j ACCEPT
                iptables -A INPUT -p $proto --dport $port -m comment --comment "$proc" -j ACCEPT
        else
                for i in ${IP[@]}; do
                        echo iptables -A INPUT -s $i -p $proto --dport $port -m comment --comment "$proc" -j ACCEPT
                        iptables -A INPUT -s $i -p $proto --dport $port -m comment --comment "$proc" -j ACCEPT
                done
        fi
done

# Записываем все остальные пакеты:
echo iptables -A INPUT -j LOG --log-prefix "diswall: "
iptables -A INPUT -j LOG --log-prefix "diswall: "

# Сохраняем правила:
echo iptables-save > /etc/iptables/rules.v4
mkdir /etc/iptables > /dev/null
iptables-save > /etc/iptables/rules.v4
echo Правила сохранены в /etc/iptables/rules.v4