import email
from email.header import decode_header
from modules.classes import MailServer, Mail, IPReport, Report
import re
from modules.serversCheck import checkIp
from requests import get
import socket
import Levenshtein
import json
import requests

def decode_name(name):
    decoded_name = decode_header(name)[0][0]
    if isinstance(decoded_name, bytes):
        #name = decoded_name.decode('utf-8')  # Assuming UTF-8 encoding
        for encoding in ['utf-8', 'iso-8859-1', 'ascii']:
            try:
                name = decoded_name.decode(encoding)
                break  # Salir del bucle si la decodificación es exitosa
            except UnicodeDecodeError:
                continue  # Intentar la siguiente codificación si falla
        else:
            # Si ninguna codificación funcionó, usa la decodificación con 'replace' para evitar errores
            name = decoded_name.decode('utf-8', errors='replace')
    else:
        name = decoded_name
    return name

def compare_email_name(email, name):
    
    lower_name = str.lower(name)
    lower_email = str.lower(str.split(email,'@')[0])
    nopunc_email = re.sub('[!@#$%^&*()-=+.,]', ' ', lower_email)
    nonum_email = re.sub(r'[0-9]+', '', nopunc_email).strip()
    distance = round(Levenshtein.distance(lower_name,nonum_email) / len(email),2)
    return distance

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
    correo.spf_record = mensaje ['Received-SPF']
    if spf_match.group(1) != 'pass':
        correo.AUTH_spf_fail = True
        print("fallo de auth")
        correo.add_peligrosidad(25)
    dkim_match = re.search(dkim_pattern, auth_result)
    correo.dkim_record = mensaje ['DKIM-Signature']
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
    #correo.add_peligrosidad((len(blacklist_sender)/15*100))
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
    domain_regex = re.compile(r'@(.+)$')
    email_match = re.search(r'<([^<>]+)>', fromField)
    name_re = re.compile(r'(.+?)(?:\s*\n\s*)?<(.*?)>')
    email_re = re.compile(r'<(.*?)>')
    print("domain "+domain_regex.search(email_match.group(1)).group(1) + " " +domain_regex.search(email_match.group(1)).group(0)) 
    if (email_match.group(1)) != returnPath:
        correo.emisor_missmatch = True
        correo.add_peligrosidad(50)
    print(fromField)
    correo.returnPath = returnPath
    name = name_re.match(fromField).group(1).strip()
    email = email_match.group(1)
    name = decode_name(name)
    print(name)
    distance = compare_email_name(email, name)
    correo.distance = distance
    correo.add_peligrosidad(distance * 5)
    print("distancia: "+str(distance))
    correo.domain = returnPath.partition('@')[2]
    with open('emailBlocklist.conf') as blocklist:
        blocklist_content = {line.rstrip() for line in blocklist.readlines()}
        print(returnPath.partition('@')[2])
        if returnPath.partition('@')[2] in blocklist_content:
            print("correo listado como spam")
            correo.add_peligrosidad(10)
            correo.spam_mail = True
    return
    

def get_ip_sender_info (ip, correo):

    codigo_titulos = {
        1: "DNS Compromise",
        2: "DNS Poisoning",
        3: "Fraud Orders",
        4: "DDoS Attack",
        5: "FTP Brute-Force",
        6: "Ping of Death",
        7: "Phishing",
        8: "Fraud VoIP",
        9: "Open Proxy",
        10: "Web Spam",
        11: "Email Spam",
        12: "Blog Spam",
        13: "VPN IP",
        14: "Port Scan",
        15: "Hacking",
        16: "SQL Injection",
        17: "Spoofing",
        18: "Brute-Force",
        19: "Bad Web Bot",
        20: "Exploited Host",
        21: "Web App Attack",
        22: "SSH",
        23: "IoT Targeted"
    }

    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': True
    }

    headers = {
        'Accept': 'application/json',
        'Key': ''
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    
    data = response.json()['data']
    
    # Crear el objeto IPReport
    ip_report = IPReport(
        ip_address=data['ipAddress'],
        country=data.get('countryName', 'Unknown'),
        isp=data.get('isp', 'Unknown'),
        domain=data.get('domain', 'Unknown'),
        abuse_score=data['abuseConfidenceScore'],
        total_reports=data['totalReports'],
        last_reported_at=data['lastReportedAt']
    )
    
    # Agregar los reportes al IPReport
    for report in data['reports']:
        ip_report.add_report(Report(
            reported_at=report['reportedAt'],
            comment=report['comment'],
            categories=report['categories'],
            reporter_country=report['reporterCountryName']
        ))
    
    for report in ip_report.reports:
        report.categories = [codigo_titulos[codigo] for codigo in report.categories]
        
    correo.ipInfo = ip_report
