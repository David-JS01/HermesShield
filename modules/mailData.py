import imaplib
import email
import os

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
        print("pasa 1")
        # Obtener el correo con el UID específico
        status, data = imap_server.fetch(uid, '(RFC822)')
        print("pasa 2")
        
        # Cerrar conexión
        imap_server.logout()
        print("pasa 2.5")
        print (status)
        # El contenido del correo está en data[0][1]
        correo_completo = data[0][1]
        print("pasa 3")
        # Parsear el correo para obtener los encabezados y el cuerpo
        mensaje = email.message_from_bytes(correo_completo)
        encabezados = mensaje.items()
        cuerpo = mensaje.get_payload()
        
        # Guardar el contenido del correo en un archivo
        nombre_archivo = f"{uid}.txt"
        with open(nombre_archivo, "wb") as archivo:
            archivo.write(correo_completo)

        print(f"Correo guardado como '{nombre_archivo}'")
        return True
    except Exception as e:
        print("Error:", e)
        return False



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