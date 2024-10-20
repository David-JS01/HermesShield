import imaplib
import email.parser
import time
import re
import msal
from modules.auth_manager import get_oauth2_token


def recuperarCorreos(correo, contraseña):

    """
    Function to retrieve emails using OAuth2 for Outlook.
    """
    imaplib.Debug = 4
    dominio = correo.split('@')[-1]
    servidor_imap = ""
    correos = []

    # Determinar el servidor IMAP y el puerto basados en el dominio
    if dominio == 'outlook.com':
        servidor_imap = 'outlook.office365.com'
        puerto = 993
    elif dominio == 'gmail.com':
        servidor_imap = 'imap.gmail.com'
        puerto = 993
    else:
        print("Dominio no compatible")
        return
    
    print(f"Connecting to IMAP server: {servidor_imap}")
    
    try:
        # Establecer conexión con el servidor IMAP
        imap_server = imaplib.IMAP4_SSL(servidor_imap)

        if dominio == 'outlook.com':
            # Use OAuth 2.0 for Outlook
            oauth2_token = get_oauth2_token()
            auth_string = f"user={correo}\1auth=Bearer {oauth2_token}\1\1"
            imap_server.authenticate('XOAUTH2', lambda x: auth_string.encode())
        else:
            # Use basic login for other providers (e.g., Gmail)
            imap_server.login(correo, contraseña)

        # Seleccionar la bandeja de entrada
        imap_server.select('inbox')

        # Buscar y mostrar los últimos 10 mensajes
        status, mensajes = imap_server.search(None, 'ALL')
        if status == 'OK':
            for num in mensajes[0].split()[-15:]:
                status, data = imap_server.fetch(num, '(BODY[HEADER])')  # Obtener solo los encabezados
                cabecera = data[0][1].decode('utf-8')  # Decodificar la cabecera a texto
                datos_correo = procesar_cabecera(cabecera, num)  # Procesar la cabecera
                correos.append(datos_correo)  # Agregar los datos a la lista

        # Cerrar conexión
        imap_server.logout()
        return correos
    except Exception as e:
        print("Error:", e)
    """
    imaplib.Debug = 4
    dominio = correo.split('@')[-1]
    servidor_imap = ""
    correos=[]
    # Determinar el servidor IMAP y el puerto basados en el dominio
    if dominio == 'outlook.com':
        servidor_imap = 'imap-mail.outlook.com'
        puerto = 993
    elif dominio == 'gmail.com':
        servidor_imap = 'imap.gmail.com'
        puerto = 993
    else:
        print("Dominio no compatible")
        return
    print(servidor_imap)
    
    try:
        # Establecer conexión con el servidor IMAP de Outlook
        imap_server = imaplib.IMAP4_SSL(servidor_imap)
        imap_server.login(correo, contraseña)

        # Seleccionar la bandeja de entrada
        imap_server.select('inbox')

        # Buscar y mostrar los últimos 10 mensajes
        status, mensajes = imap_server.search(None, 'ALL')
        if status == 'OK':
            for num in mensajes[0].split()[-10:]:
                status, data = imap_server.fetch(num, '(BODY[HEADER])')  # Obtener solo los encabezados
                cabecera = data[0][1].decode('utf-8')  # Decodificar la cabecera a texto
                datos_correo=procesar_cabecera(cabecera, num)  # Procesar la cabecera
                correos.append(datos_correo)  # Agregar los datos a la lista

        # Cerrar conexión
        imap_server.logout()
        return correos
    except Exception as e:
        print("Error:", e)
"""
def procesar_cabecera(cabecera, uid):
    # Parsear la cabecera con la librería email.parser
    parser = email.parser.HeaderParser()
    mensaje = parser.parsestr(cabecera)
    
    
    remitente = mensaje['From']
    asunto = mensaje['Subject']
    fecha = mensaje['Date']
    print ("id: ", uid)
    regex_correo = r'<([^>]+)>'
    coincidencias = re.search(regex_correo, remitente)
    if coincidencias:
        remitente=coincidencias.group(1)
    received = mensaje.get_all('Received')
    tam=0
    if received:
        tam=len(received)

    return {'Remitente': remitente, 'Asunto': asunto, 'Fecha': fecha, 'UID': uid.decode(), 'Tam': tam}