import os
import sys
import subprocess
import platform
import webbrowser
import time

def create_virtualenv(env_dir):
    print("Creando entorno virtual...")
    subprocess.check_call([sys.executable, "-m", "venv", env_dir])

def install_dependencies(env_dir):
    print("Instalando dependencias...")
    if platform.system() == "Windows":
        pip_executable = os.path.join(env_dir, "Scripts", "pip.exe")
    else:
        pip_executable = os.path.join(env_dir, "bin", "pip")
    subprocess.check_call([pip_executable, "install", "--upgrade", "pip"])
    subprocess.check_call([pip_executable, "install", "-r", "requirements.txt"])

def run_flask_app(env_dir):
    print("Iniciando la aplicación Flask...")
    if platform.system() == "Windows":
        python_executable = os.path.join(env_dir, "Scripts", "python.exe")
    else:
        python_executable = os.path.join(env_dir, "bin", "python")
    
    # Iniciar Flask en un proceso separado
    if platform.system() == "Windows":
        # Usa 'start' para abrir en una nueva ventana
        subprocess.Popen([python_executable, "app.py"], creationflags=subprocess.CREATE_NEW_CONSOLE)
    else:
        # Ejecuta en segundo plano
        subprocess.Popen([python_executable, "app.py"])
    
    # Esperar unos segundos para asegurarse de que Flask se inicie
    time.sleep(5)

def open_browser(url):
    print(f"Abriendo el navegador en {url}...")
    webbrowser.open(url)

def main():
    env_dir = "env"

    # Verificar si el entorno virtual ya existe
    if not os.path.exists(env_dir):
        create_virtualenv(env_dir)
        install_dependencies(env_dir)
    else:
        print("Entorno virtual ya existe. Saltando creación e instalación de dependencias.")

    run_flask_app(env_dir)
    open_browser("http://127.0.0.1:5000/")

if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print(f"Error durante la ejecución: {e}")
        sys.exit(1)
