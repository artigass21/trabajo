#!/bin/bash

#869469, Artigas Subiras, Adrián, T, 1, A
#873026, Becerril Granada, Adrián, T, 1, A

# Limpiamos todas las reglas anteriores
iptables -F
iptables -X
iptables -Z
iptables -t nat -F

# Crear nuevas cadenas para logging
iptables -N LOG_INPUT_ACCEPT
iptables -A LOG_INPUT_ACCEPT -j LOG --log-level 7 --log-prefix "[INPUT_ACCEPT]: "
iptables -A LOG_INPUT_ACCEPT -j ACCEPT

iptables -N LOG_INPUT_DROP
iptables -A LOG_INPUT_DROP -j LOG --log-level 7 --log-prefix "[INPUT_DROP]: "
iptables -A LOG_INPUT_DROP -j DROP

iptables -N LOG_FORWARD_DROP
iptables -A LOG_FORWARD_DROP -j LOG --log-level 7 --log-prefix "[FORWARD_DROP]: "
iptables -A LOG_FORWARD_DROP -j DROP

# Establecemos políticas por defecto
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitimos todo el tráfico en las redes internas (intranet)
iptables -A FORWARD -i enp0s8 -o enp0s8 -j ACCEPT  # Red interna 1
iptables -A FORWARD -i enp0s9 -o enp0s9 -j ACCEPT  # Red interna 2
iptables -A FORWARD -i enp0s10 -o enp0s10 -j ACCEPT # Red interna 3

# Permitimos tráfico de la intranet hacia la extranet (hacia NAT)
iptables -A FORWARD -i enp0s8 -o enp0s3 -j ACCEPT  # Red interna 1 a NAT
iptables -A FORWARD -i enp0s9 -o enp0s3 -j ACCEPT  # Red interna 2 a NAT
iptables -A FORWARD -i enp0s10 -o enp0s3 -j ACCEPT # Red interna 3 a NAT

# Permitimos tráfico del servidor web (debian2) y ssh (debian5) desde la extranet
iptables -A FORWARD -i enp0s10 -o enp0s8 -p tcp --dport 80 -d 192.168.31.2 -m state --state NEW,ESTABLISHED -j ACCEPT # Web desde Host-only a debian2 (Red interna 1)
iptables -A FORWARD -i enp0s10 -o enp0s10 -p tcp --dport 22 -d 192.168.33.1 -m state --state NEW,ESTABLISHED -j ACCEPT # SSH desde Host-only a debian5 (Red interna 3)
iptables -A FORWARD -i enp0s8 -o enp0s10 -p tcp --sport 80 -s 192.168.31.2 -m state --state ESTABLISHED -j ACCEPT
iptables -A FORWARD -i enp0s10 -o enp0s10 -p tcp --sport 22 -s 192.168.33.1 -m state --state ESTABLISHED -j ACCEPT

# Permitir respuestas a pings desde la intranet pero no desde la extranet
iptables -A INPUT -i enp0s8 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i enp0s9 -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i enp0s10 -p icmp --icmp-type echo-request -j DROP

# NAT para todo el tráfico desde la intranet a la extranet usando la IP pública del firewall (192.168.56.1)
iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE

# Todo el tráfico desde la extranet hacia la intranet debe parecer que va hacia el firewall
iptables -t nat -A PREROUTING -i enp0s10 -p tcp --dport 80 -j DNAT --to 192.168.31.2
iptables -t nat -A PREROUTING -i enp0s10 -p tcp --dport 22 -j DNAT --to 192.168.33.1

# Logging para el tráfico denegado
iptables -A INPUT -j LOG_INPUT_DROP
iptables -A FORWARD -j LOG_FORWARD_DROP

# Guardar las reglas para que se apliquen al reiniciar
iptables-save > /etc/iptables/rules.v4