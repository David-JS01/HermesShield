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
    percTotal=0
    blacklist=[]
    for servers in serverList:
        blacklist=checkIp(servers.domain)
        servers.blacklists=blacklist.copy()
        servers.perc= len(blacklist) / 30
        print("Server en: " + str(len(blacklist)) + " listas nivel de peligrosidad: " + str(servers.perc) )
        percTotal+=servers.perc
        
    
    
    print("fiabilidad correo: " + str(100-percTotal) + "%")
    return str(100-percTotal), serverList
    
    return ""