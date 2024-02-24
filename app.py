from flask import Flask, render_template, url_for, request, redirect
from cryptography.fernet import Fernet
import os

app = Flask(__name__)
login_file="./login.txt"
correoUsuario="hola"
key="h"

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
    
    print("datos a cifrar "+ contraseña +"contraseña pa encriptar " + str(key))
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
            print("datos "+ encrypted_password +"contraseña pa desencriptar " + str(clave))
            cipher_suite = Fernet(clave)
            contrasena_desencriptada = cipher_suite.decrypt(encrypted_password).decode()
            # devolvemos credenciales.
            return correo, contrasena_desencriptada

    except FileNotFoundError:
        print("El archivo login.txt no existe.")
        return None, None


@app.route('/')
def index():
    
    if not verificar_credenciales(login_file):
        return redirect("/login")
    correo, contraseña = recuperar_credenciales()
    print("Correo:", correo)
    print("Contraseña:", contraseña)
    
    return render_template("index.html", username=correoUsuario, emails=emails)


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
    

@app.route('/logout')
def logout():
    if os.path.isfile(login_file):
        # Si el archivo no está vacío, vaciar su contenido
        open(login_file, 'w').close()
#contrasena_desencriptada = cipher_suite.decrypt(contrasena_encriptada_leida).decode()
    return redirect('/')


if __name__=="__main__":
    app.run(debug=True)