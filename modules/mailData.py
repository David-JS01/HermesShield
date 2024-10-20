import imaplib
import email
import os
import msal
from modules.auth_manager import get_oauth2_token


def recuperarCorreoPorUID(correo, uid):
    """
    Retrieve a specific email by UID from an Outlook account using OAuth 2.0.
    """
    dominio = correo.split('@')[-1]
    servidor_imap = ""
    
    # Determinar el servidor IMAP basado en el dominio
    if dominio == 'outlook.com':
        servidor_imap = 'outlook.office365.com'
        puerto = 993
    elif dominio == 'gmail.com':
        servidor_imap = 'imap.gmail.com'
        puerto = 993
    else:
        print("Dominio no compatible")
        return None
    
    try:
        # Establecer conexión con el servidor IMAP de Outlook
        imap_server = imaplib.IMAP4_SSL(servidor_imap)

        if dominio == 'outlook.com':
            # Use OAuth 2.0 for Outlook
            oauth2_token = get_oauth2_token()
            auth_string = f"user={correo}\1auth=Bearer {oauth2_token}\1\1"
            imap_server.authenticate('XOAUTH2', lambda x: auth_string.encode())
        else:
            # For other services (like Gmail), you can still use basic auth
            imap_server.login(correo, contraseña)

        # Seleccionar la bandeja de entrada
        imap_server.select('inbox')
        
        # Obtener el correo con el UID específico
        status, data = imap_server.fetch(uid, '(RFC822)')
        
        # Cerrar conexión
        imap_server.logout()

        if status != 'OK':
            print("Error al buscar el correo.")
            return None

        # El contenido del correo está en data[0][1]
        correo_completo = data[0][1]
        
        # Parsear el correo para obtener los encabezados y el cuerpo
        mensaje = email.message_from_bytes(correo_completo)
        encabezados = mensaje.items()
        cuerpo = mensaje.get_payload()
        
        folder_name = f"folder_{uid}"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # Guardar el contenido del correo en un archivo
        nombre_archivo = f"{uid}.txt"
        with open(nombre_archivo, "wb") as archivo:
            archivo.write(correo_completo)

        print(f"Correo guardado como '{nombre_archivo}'")

        # Guardar los adjuntos en la carpeta
        if mensaje.is_multipart():
            for part in mensaje.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        file_path = os.path.join(folder_name, filename)
                        with open(file_path, 'wb') as f:
                            f.write(part.get_payload(decode=True))
                        print(f'Adjunto guardado como {file_path}')

        return True
    except Exception as e:
        print("Error:", e)
        return False

"""
def recuperarCorreoPorUID(correo, contraseña, uid):
    dominio = correo.split('@')[-1]
    servidor_imap = ""
    
    # Determinar el servidor IMAP basado en el dominio
    if dominio == 'outlook.com':
        servidor_imap = 'imap-mail.outlook.com'
        puerto = 993
    elif dominio == 'gmail.com':
        servidor_imap = 'imap.gmail.com'
        puerto = 993
    else:
        print("Dominio no compatible")
        return None
    
    try:
        # Establecer conexión con el servidor IMAP de Outlook
        imap_server = imaplib.IMAP4_SSL(servidor_imap)
        imap_server.login(correo, contraseña)

        # Seleccionar la bandeja de entrada
        imap_server.select('inbox')
        
        # Obtener el correo con el UID específico
        status, data = imap_server.fetch(uid, '(RFC822)')
        
        
        # Cerrar conexión
        imap_server.logout()
        
        print (status)
        # El contenido del correo está en data[0][1]
        correo_completo = data[0][1]
        
        # Parsear el correo para obtener los encabezados y el cuerpo
        mensaje = email.message_from_bytes(correo_completo)
        encabezados = mensaje.items()
        cuerpo = mensaje.get_payload()
        
        folder_name = f"folder_{uid}"
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

        # Guardar el contenido del correo en un archivo
        nombre_archivo = f"{uid}.txt"
        with open(nombre_archivo, "wb") as archivo:
            archivo.write(correo_completo)

        
        print(f"Correo guardado como '{nombre_archivo}'")

        # Guardar los adjuntos en la carpeta
        if mensaje.is_multipart():
            for part in mensaje.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        file_path = os.path.join(folder_name, filename)
                        with open(file_path, 'wb') as f:
                            f.write(part.get_payload(decode=True))
                        print(f'Adjunto guardado como {file_path}')



        return True
    except Exception as e:
        print("Error:", e)
        return False


"""
def leer_correo_archivo(archivo):
    with open(archivo, 'r', encoding='utf-8') as f:
        correo_raw = f.read()

    mensaje = email.message_from_string(correo_raw)
    remitente = mensaje['From']
    destinatario = mensaje['To']
    asunto = mensaje['Subject']
    fecha = mensaje['Date']

    # Obtener el contenido del cuerpo en formato HTML
    contenido_html = None
    for part in mensaje.walk():
        if part.get_content_type() == 'text/html':
            contenido_html = part.get_payload(decode=True).decode(part.get_content_charset())

    return {'Remitente': remitente, 'Destinatario': destinatario, 'Asunto': asunto, 'Fecha': fecha, 'Contenido_HTML': contenido_html}