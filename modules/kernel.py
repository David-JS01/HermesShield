import email
from modules.classes import MailServer, Mail, URL, sandbox, File
import re
from modules.serversCheck import checkIp
from requests import get
from modules.headers import checkARC, checkAUTH, checkFrom, get_ip_sender_info
from modules.body import lexical_analyzer, ia_model_analyzer, URL_analysis, FILE_analysis
import socket
import os


def analisisDeSeguridad(file, uid):
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

    correo.From = mensaje['From']
    correo.To = mensaje['To']
    correo.Subject = mensaje['Subject']
    correo.Date = mensaje['Date']

    contenido_html = None
    for part in mensaje.walk():
        if part.get_content_type() == 'text/html':
            contenido_html = part.get_payload(decode=True).decode(part.get_content_charset())
    correo.text = contenido_html

    ################################CABECERAS DEL EMAIL#############################################################################

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
    for servers in correo.servidores:
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
    checkFrom(mensaje, correo)

    auth_result = mensaje['Authentication-Results']
    sender_ip = re.search(ip_pattern, auth_result)
    correo.ip_sender = sender_ip.group(1)
    #get_ip_sender_info(sender_ip.group(1)) #de momento comentado para evitar gasto de recursos en pruebas


    ################################ CUERPO DEL EMAIL ###################################################
    f1 = lexical_analyzer(mensaje, correo)
    f2 = ia_model_analyzer(mensaje, correo)
    percTotal = percTotal + f1 + f2
    URL_analysis(mensaje, correo)

    folder_name = f"folder_{uid}"
    if os.path.exists(folder_name):
        print("adjuntos encontrados")
        try:
        # Iterate over all items in the directory
            for item in os.listdir(folder_name):
                item_path = os.path.join(folder_name, item)
            
                # Check if the item is a file
                if os.path.isfile(item_path):
                    file_size = os.path.getsize(item_path)
                    print(f"File: {item_path} Size: {file_size} bytes")
                    url = "https://www.virustotal.com/api/v3/files"
                    if file_size > 32000000:
                        print("max size getting url...")
                        url = get_url_file()
                    file = FILE_analysis(url, item_path)
                    correo.add_file(file)
        except Exception as e:
            print(f"An error occurred: {e}")

    context = correo.__dict__
    context['servidores'] = [s.__dict__ for s in correo.servidores]
    context['urls'] = [u.__dict__ for u in correo.urls]

    # Ensure all 'engine_analysis' elements in each URL are converted to dictionaries
    for url in context['urls']:
        url['engine_analysis'] = [e.__dict__ for e in url['engine_analysis']]

    context['files'] = [f.__dict__ for f in correo.files]

    # Ensure all 'engine_analysis' elements in each file are converted to dictionaries
    for file in context['files']:
        file['engine_analysis'] = [e.__dict__ for e in file['engine_analysis']]
        # Handle sandboxResult if it exists and is not a list
        if file['sandboxResult'] and isinstance(file['sandboxResult'], sandbox):
            file['sandboxResult'] = file['sandboxResult'].__dict__
    print(context)
    percTotal = correo.peligrosidad
    print("fiabilidad correo: " + str(100-percTotal) + "%")
    return str(100-percTotal), serverList, context
    
    return ""