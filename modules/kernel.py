import email
from modules.classes import MailServer, Mail
import re
from modules.serversCheck import checkIp
from requests import get
from modules.headers import checkARC, checkAUTH
import socket


def analisisDeSeguridad(file):
    spf_pattern = r'spf=(\w+)'
    dkim_pattern = r'dkim=(\w+)'
    dmarc_pattern = r'dmarc=(\w+)'
    cv_pattern = r'cv=(\w+)'
    arc_pattern = r'arc=(\w+)'
    compauth_pattern = r'compauth=(\w+)'
    ip_pattern = re.compile(r'sender IP is (\d+\.\d+\.\d+\.\d+)')
    ip_pattern2 = re.compile(r'IP Address: (\d+\.\d+\.\d+\.\d+)')
    domain_pattern = re.compile(r'header\.from=([^\s;]+)')
    correo = Mail()
    with open(file, 'r', encoding='utf-8') as f:
        correo_raw = f.read()

    mensaje = email.message_from_string(correo_raw)
    #Se analizan todos los campos Recieved, obteniendo direccion ip y dominio para posteriormente comprobar contra blacklists publicas
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
                correo.add_servidor(server)
    percTotal=0
    blacklist=[]
    for servers in serverList:
        blacklist=checkIp(servers.domain)
        servers.blacklists=blacklist.copy()
        servers.perc= len(blacklist) / 15
        print("Server en: " + str(len(blacklist)) + " listas nivel de peligrosidad: " + str(servers.perc) )
        percTotal+=servers.perc
        
    percTotal=percTotal*100
    correo.add_peligrosidad(percTotal)
    #se finaliza la comprobacion de campos Recieved
    #print("ARC "+ mensaje['ARC-Seal'])
    #Comprobacion de los campos ARC del correo.
    if checkARC(mensaje, correo):
        print("ARC analizado")
    else:
        print("Sin ARC para analizar")

    print("correo checkeado? " + str(correo.checked))    
    
    
    pel = checkAUTH(mensaje, correo)
    #percTotal=percTotal+pel
    percTotal = correo.peligrosidad
    #habria que checkear el campo DKIM-Signature pero en correo Outlook siempre falla.

    print("fiabilidad correo: " + str(100-percTotal) + "%")
    return str(100-percTotal), serverList
    
    return ""