import email
from modules.classes import MailServer, Mail
import re
from modules.serversCheck import checkIp
from requests import get
import socket

def checkARC (mensaje, correo):
    spf_pattern = r'spf=(\w+)'
    dkim_pattern = r'dkim=(\w+)'
    dmarc_pattern = r'dmarc=(\w+)'
    cv_pattern = r'cv=(\w+)'
    arc_pattern = r'arc=(\w+)'
    arc_seal_fields=mensaje.get_all('ARC-Seal')
    if arc_seal_fields:
        for arcSeal in arc_seal_fields:
            cv_match = re.search(cv_pattern, arcSeal)
            if cv_match:
                if cv_match.group(1) == 'fail':
                    correo.ARC_cv_fail = True
                    correo.add_peligrosidad(15)
                if cv_match.group(1) == 'none':
                    print("Warning cv=none detectado")
        arc_auth_fields = mensaje.get_all('ARC-Authentication-Results')
        for arcAuth in arc_auth_fields:
            spf_match = re.search(spf_pattern, arcAuth)
            if spf_match:
                if spf_match.group(1) == 'fail':
                    correo.ARC_spf_fail = True
                    correo.add_peligrosidad(15)
                if spf_match.group(1) == 'none':
                    print("Warning spf=none detectado")
            dmarc_match = re.search(dmarc_pattern, arcAuth)
            if dmarc_match:
                if dmarc_match.group(1) == 'fail':
                    correo.ARC_dmarc_fail = True
                    correo.add_peligrosidad(15)
                if dmarc_match.group(1) == 'none':
                    print("Warning dmarc=none detectado")
            dkim_match = re.search(dkim_pattern, arcAuth)
            if dkim_match:
                if dkim_match.group(1) == 'fail':
                    correo.ARC_dkim_fail = True
                    correo.add_peligrosidad(15)
                if dkim_match.group(1) == 'none':
                    print("Warning dkim=none detectado")
            arc_match = re.search(arc_pattern, arcAuth)
            if arc_match:
                if arc_match.group(1) == 'fail':
                    correo.ARC_fail = True
                    correo.add_peligrosidad(15)
                if arc_match.group(1) == 'none':
                    print("Warning arc=none detectado")
        correo.checked=True
        return True
    else:
        return False


def checkAUTH (mensaje, correo):
    peligrosidad = 0
    spf_pattern = r'spf=(\w+)'
    dkim_pattern = r'dkim=(\w+)'
    dmarc_pattern = r'dmarc=(\w+)'
    cv_pattern = r'cv=(\w+)'
    arc_pattern = r'arc=(\w+)'
    compauth_pattern = r'compauth=(\w+)'
    ip_pattern = re.compile(r'sender IP is (\d+\.\d+\.\d+\.\d+)')
    ip_pattern2 = re.compile(r'IP Address: (\d+\.\d+\.\d+\.\d+)')
    domain_pattern = re.compile(r'header\.from=([^\s;]+)')
    auth_result = mensaje['Authentication-Results']
    print(auth_result)
    spf_match = re.search(spf_pattern, auth_result)
    if spf_match.group(1) != 'pass':
        correo.AUTH_spf_fail = True
        print("fallo de auth")
        correo.add_peligrosidad(25)
    dkim_match = re.search(dkim_pattern, auth_result)
    if dkim_match.group(1) != 'pass':
        correo.AUTH_dkim_fail = True
        print("fallo de auth")
        correo.add_peligrosidad(25)
    dmarc_match = re.search(dmarc_pattern, auth_result)
    if dmarc_match.group(1) != 'pass':
        correo.AUTH_dmarc_fail = True
        print("fallo de auth")
        correo.add_peligrosidad(25)
    compauth_match = re.search(compauth_pattern, auth_result)
    if compauth_match.group(1) != 'pass':
        correo.AUTH_compauth_fail = True
        print("fallo de auth")
        correo.add_peligrosidad(25)
    
    sender_ip = re.search(ip_pattern, auth_result)
    blacklist_sender = checkIp(sender_ip.group(1))
    print("listas: "+str(len(blacklist_sender)))
    correo.add_peligrosidad((len(blacklist_sender)/15*100))
    sender_domain = domain_pattern.search(auth_result)
    print(sender_domain.group(1))
    sender_domain_ip = None
    try:
        sender_domain_ip = socket.gethostbyname(sender_domain.group(1))
    except socket.gaierror:
        pass
    #geoip = get('http://api.hackertarget.com/geoip/?q='
    #                       + sender_domain.group(1)).text
    #sender_domain_ip = re.search(ip_pattern2, geoip)
    #print(sender_domain_ip.group(1))
    if sender_domain_ip:
        blacklist_domain_sender=checkIp(sender_domain_ip)
        print("listas:"+str(len(blacklist_domain_sender)))
        correo.add_peligrosidad((len(blacklist_domain_sender)/15*100))
    return 0

def checkFrom(mensaje, correo):
    peligrosidad = 0
    fromField = mensaje['From']
    returnPath = mensaje['Return-Path']
    email_match = re.search(r'<([^<>]+)>', fromField)
    if email_match.group(1) != returnPath:
        correo.emisor_missmatch = True
        peligrosidad = peligrosidad + 50
