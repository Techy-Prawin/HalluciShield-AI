import os

def ping_host(hostname):
    result = os.system("ping -c 1 " + hostname)
    return result

ping_host("127.0.0.1")