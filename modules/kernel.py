import email
from modules.classes import MailServer
import re
from modules.serversCheck import checkIp


def analisisDeSeguridad(file):
    with open(file, 'r', encoding='utf-8') as f:
        correo_raw = f.read()

    mensaje = email.message_from_string(correo_raw)
    
    received = mensaje.get_all('Received')
    regex = r"from\s+([\w.-]+)\s*\(\[?([^\]\s]+)\]?\)"
    
    serverList=[]
    if received:
        for address in received:
            match = re.search(regex, address)
            if match:
                server=MailServer()
                server.ip_address=match.group(1)
                server.domain=match.group(2)
                serverList.append(server)
    
    for servers in serverList:
        checkIp(servers.domain)
    
    return ""