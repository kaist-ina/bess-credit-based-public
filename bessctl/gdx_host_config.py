import socket

def host_setup():
    host_ip_addrs = []
    hostname = socket.gethostname()
    if hostname == "kiwi3":
        host_ip_addrs.append("10.7.0.103/24")
        host_ip_addrs.append("10.7.1.103/24")
    elif hostname == "kiwi4":
        host_ip_addrs.append("10.7.0.104/24")
        host_ip_addrs.append("10.7.1.104/24")
    elif hostname == "iris1":
        host_ip_addrs.append("10.7.0.81/24")
        host_ip_addrs.append("10.7.1.81/24")
    elif hostname == "iris2":
        host_ip_addrs.append("10.7.0.82/24")
        host_ip_addrs.append("10.7.1.82/24")
    elif hostname == "iris3":
        host_ip_addrs.append("10.7.0.83/24")
        host_ip_addrs.append("10.7.1.83/24")
    elif hostname == "iris4":
        host_ip_addrs.append("10.7.0.84/24")
        host_ip_addrs.append("10.7.1.84/24")
    return host_ip_addrs