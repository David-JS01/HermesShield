from flask import Flask, render_template, url_for, request, redirect, flash, make_response
from cryptography.fernet import Fernet
import os
from modules.mails import recuperarCorreos
from modules.mailData import recuperarCorreoPorUID, leer_correo_archivo
from modules.kernel import analisisDeSeguridad
import shutil
from weasyprint import HTML, CSS
from datetime import datetime
import hashlib
import signal
import sys



app = Flask(__name__)
app.secret_key = 'clave'
login_file="./login.txt"
correoUsuario="hola"
key="h"
dicts = [None] * (30 + 1)

def calculate_email_hash_from_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            email_content = file.read()
        
        # Crear un objeto hash SHA-256
        sha256_hash = hashlib.sha256()
        
        # Actualizar el objeto hash con el contenido del correo
        sha256_hash.update(email_content.encode('utf-8'))
        
        # Obtener el valor hexadecimal del hash
        email_hash = sha256_hash.hexdigest()
        
        return email_hash
    except FileNotFoundError:
        return "File not found"
    except Exception as e:
        return f"An error occurred: {e}"

def verificar_credenciales(archivo):
    try:
        with open(archivo, 'r') as f:
            linea=f.readline().strip()
            partes = linea.split(':')
            if len(partes) == 2:
                correo, hash=partes
                if '@' in correo:
                    global correoUsuario
                    correoUsuario=correo
                    return True
            return False
    except FileNotFoundError:
        print(f"El archivo {archivo} no se encuentra.")
        return False


def guardar_credenciales(correo, contraseña):
    # Comprobar si el archivo login.txt está vacío
    if os.path.isfile("login.txt") and os.stat("login.txt").st_size != 0:
        # Si el archivo no está vacío, vaciar su contenido
        open("login.txt", 'w').close()

    global key
    key = Fernet.generate_key()
    
    print("datos a cifrar "+ contraseña +"contraseña para encriptar " + str(key))
    c = Fernet(key)
    contraseña_encriptada = c.encrypt(contraseña.encode()).decode()

    try:
        # Guardar el correo y la contraseña en el archivo login.txt
        with open("login.txt", 'a') as archivo:
            archivo.write(f"{correo}:{contraseña_encriptada}\n")
        return True
    except Exception as e:
        return False


def recuperar_credenciales():
    try:
        with open(login_file, 'r') as file:
            line = file.readline().strip().split(':')
            correo = line[0]
            encrypted_password = line[1]

            clave=key
            print("datos "+ encrypted_password +"contraseña para desencriptar " + str(clave))
            cipher_suite = Fernet(clave)
            contrasena_desencriptada = cipher_suite.decrypt(encrypted_password).decode()
            # devolvemos credenciales.
            return correo, contrasena_desencriptada

    except FileNotFoundError:
        print("El archivo login.txt no existe.")
        return None, None


def cleanup():
    # Esta función se ejecutará al finalizar la aplicación Flask
    print("La aplicación se ha detenido. Limpiando recursos...")
    if os.path.isfile(login_file):
        # Si el archivo no está vacío, vaciar su contenido
        open(login_file, 'w').close()
    
    archivos = os.listdir()
    
    # Iterar sobre cada archivo en el directorio
    for archivo in archivos:
        # Verificar si el archivo es un archivo .txt y no es "login.txt"
        if archivo.endswith('.txt') and archivo != 'login.txt':
            # Eliminar el archivo
            os.remove(archivo)
    
    current_dir = os.getcwd()
    
    # Iterate over all files and directories in the current directory
    for item in os.listdir(current_dir):
        # Check if the item is a directory and starts with "folder_"
        if os.path.isdir(item) and item.startswith("folder_"):
            # Check if the rest of the name is numeric (indicating a UID)
            uid_suffix = item[7:]  # Get the part after "folder_"
            if uid_suffix.isnumeric():
                # Construct the full path to the directory
                dir_path = os.path.join(current_dir, item)
                # Delete the directory and its contents
                shutil.rmtree(dir_path)
                print(f"Deleted folder: {dir_path}")

@app.route('/')
def index():
    
    if not verificar_credenciales(login_file):
        return redirect("/login")
    correo, contraseña = recuperar_credenciales()
    print("Correo:", correo)
    print("Contraseña:", contraseña)
    emails=recuperarCorreos(correo, contraseña)
    #dicts = [None] * (len(emails) + 1)
    return render_template("index.html", username=correo, emails=emails)


@app.route('/login', methods=['POST', 'GET'])
def login():

    if request.method == 'POST':
        correo = request.form['username']
        contraseña = request.form['password']
        if guardar_credenciales(correo, contraseña):
            global correoUsuario
            correoUsuario=correo
            return redirect("/")
        else:
            return "error al iniciar sesion"
    else:
        return render_template('login.html')


@app.route('/mail/<uid>')
def showMail(uid):
    correo, contraseña=recuperar_credenciales()
    if not os.path.isfile(f"{uid}.txt"):
        if not recuperarCorreoPorUID(correo, contraseña, uid):
            return "error en la recuperación del correo"
    datos_correo=leer_correo_archivo(f"{uid}.txt")
    #flash('analizando email')
    seguridad, servidores, dicti=analisisDeSeguridad(f"{uid}.txt", uid)
    for s in servidores:
        print("len "+ str(len(s.blacklists)))
    servers=[{'nombre': servidor.ip_address, 'blacklists': len(servidor.blacklists)} for servidor in servidores]

    dicts[int(uid)]=dicti
    return render_template('mailView.html', datos=datos_correo, fiabilidad=seguridad, servers=servers)

@app.route('/mail/<uid>/report')
def showReport(uid):
    hash = calculate_email_hash_from_file(f"{uid}.txt")
    return render_template('report.html', uid=uid, analysis = dicts[int(uid)], hash=hash)

@app.route('/mail/<uid>/pdf')
def generate_pdf(uid):
    # Generar el HTML a partir de una plantilla
    current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hash = calculate_email_hash_from_file(f"{uid}.txt")
    html = render_template('example.html', uid=uid, analysis = dicts[int(uid)], current_date=current_date, hash=hash)  # Asegúrate de tener una plantilla HTML
    css_path = os.path.join(app.root_path, 'static/css/example.css')
    pdf = HTML(string=html).write_pdf(stylesheets=[CSS(filename=css_path)])
    nombre = f"report_{uid}.pdf"

    # Crear una respuesta de tipo archivo PDF
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={nombre}'
    return response


@app.route('/logout')
def logout():
    cleanup()
    return redirect('/')

def signal_handler(sig, frame):
    print("Interrupción recibida, ejecutando cleanup...")
    cleanup()
    sys.exit(0)

if __name__=="__main__":
    signal.signal(signal.SIGINT, signal_handler)
    try:
        app.run(debug=True)
    finally:
        cleanup()