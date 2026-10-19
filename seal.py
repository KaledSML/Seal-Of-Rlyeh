#!/usr/bin/env python3
"""
Seal of R'lyeh
--------------
Un guardián arcano para proteger tus archivos y carpetas más preciados.

Comandos disponibles:
    python seal.py setup     -> Configura y cifra la carpeta objetivo
    python seal.py unlock    -> Intenta abrir el cofre (tienes 3 intentos)
    python seal.py status    -> Muestra el estado actual del cofre
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Importamos las funciones principales desde nuestro paquete 'core'
from core.vault import seal_folder, unseal_folder
from core.chaos import relocate_vault
from core.grimoire import generate_glyph_image, send_panic_email

# Ruta por defecto del archivo de configuración
DEFAULT_CONFIG_PATH = Path("config.json")
DESKTOP = Path.home() / "Desktop"

def load_config(path: Path) -> dict:
    """Carga la configuración desde el archivo JSON."""
    if not path.exists():
        print(f"[X] No se encontró el archivo de configuración en '{path}'. Ejecuta primero 'setup'.")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_config(path: Path, config: dict):
    """Guarda la configuración actualizada en el archivo JSON."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

def cmd_setup(args):
    """Comando para configurar y cifrar una carpeta por primera vez."""
    print("=== INVOCANDO SEAL OF R'LYEH ===")
    target_input = input("Ruta de la carpeta a proteger: ").strip('"')
    
    if not os.path.exists(target_input):
        print("[X] La ruta ingresada no existe.")
        return

    password = input("Clave maestra (la necesitarás para abrirlo): ").strip()
    confirm_pw = input("Repite la clave maestra: ").strip()

    if password != confirm_pw:
        print("[X] Las contraseñas no coinciden. Cancelando ritual.")
        return

    email = input("Tu correo electrónico (para alertas de pánico): ").strip()
    smtp_server = input("Servidor SMTP (ej. smtp.gmail.com) [Presiona Enter para default]: ").strip()
    if not smtp_server:
        smtp_server = "smtp.gmail.com"

    app_password = input("Contraseña de aplicación de tu correo: ").strip()
    
    # Guardamos la contraseña de aplicación en la sesión mediante variable de entorno
    os.environ["RLYEH_EMAIL_PASS"] = app_password

    print("\n[~] Comprimiendo y cifrando la carpeta...")
    try:
        vault_path, salt = seal_folder(target_input, password)
    except Exception as e:
        print(f"[X] Error durante el cifrado: {e}")
        return

    # Creamos el mapa de configuración inicial
    config = {
        "target_folder": target_input,
        "vault_path": vault_path,
        "salt": list(salt),  # Convertimos los bytes de la sal a lista para JSON
        "attempts_left": 3,
        "state": "sealed",
        "email_config": {
            "sender": email,
            "smtp_server": smtp_server,
            "smtp_port": 465
        }
    }

    save_config(Path(args.config), config)
    print(f"\n[OK] ¡Cofre sellado con éxito!")
    print(f"     El objetivo fue reemplazado por el cofre: {vault_path}\n")

def cmd_unlock(args):
    """Comando para intentar abrir el cofre."""
    config_path = Path(args.config)
    config = load_config(config_path)

    if config["state"] == "destroyed":
        print("[X] El cofre ha sido destruido o profanado.")
        return

    if config["state"] == "quarantined":
        print("[!] ATENCIÓN: El cofre se encuentra en cuarentena y fue mudado de lugar.")
        print("    Revisa tu correo o el archivo PNG de glifos en tu Escritorio.")

    print(f"Intentos restantes: {config['attempts_left']}")
    password = input("Clave de desbloqueo: ").strip()

    vault_path = config["vault_path"]
    salt = bytes(config["salt"])

    # Intentamos descifrar y restaurar
    success = unseal_folder(vault_path, salt, password)

    if success:
        print("\n[OK] ¡Clave correcta! El cofre se ha abierto y la carpeta fue restaurada.")
        config["state"] = "unlocked"
        config["attempts_left"] = 3
        save_config(config_path, config)
    else:
        config["attempts_left"] -= 1
        print(f"\n[X] Clave incorrecta. Te quedan {config['attempts_left']} intento(s).")

        if config["attempts_left"] <= 0:
            print("\n[!] ¡Se han agotado los intentos! Despertando al guardián...")

            # 1. Ejecutar Caos (mudar el cofre a una carpeta aleatoria dentro de Documentos)
            new_vault_path = relocate_vault(vault_path)
            config["vault_path"] = new_vault_path
            config["state"] = "quarantined"

            # 2. Ejecutar Grimorio (generar imagen PNG con los glifos de Nug-Soth)
            glyph_path = DESKTOP / "rlyeh_glifos_clave.png"
            generate_glyph_image(password, str(glyph_path))

            # 3. Enviar correo de pánico
            app_pass = os.environ.get("RLYEH_EMAIL_PASS")
            if not app_pass:
                app_pass = input("Introduce tu contraseña de aplicación de correo para enviar la alerta: ").strip()

            if app_pass:
                try:
                    send_panic_email(
                        sender_email=config["email_config"]["sender"],
                        app_password=app_pass,
                        smtp_host=config["email_config"]["smtp_server"],
                        attachment_path=str(glyph_path)
                    )
                    print("[+] Alerta enviada a tu correo electrónico.")
                except Exception as e:
                    print(f"[!] No se pudo enviar el correo: {e}")

            print(f"[+] El cofre ha sido mudado a: {new_vault_path}")
            print(f"[+] Se dejó la pista en Nug-Soth en tu Escritorio: {glyph_path.name}")

        save_config(config_path, config)

def cmd_status(args):
    """Muestra el estado actual del cofre."""
    config = load_config(Path(args.config))
    print(json.dumps(config, indent=4, ensure_ascii=False))

def main():
    parser = argparse.ArgumentParser(description="Seal of R'lyeh - Guardián arcano de carpetas")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Ruta del archivo de configuración")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("setup", help="Configurar y cifrar una carpeta")
    subparsers.add_parser("unlock", help="Intentar abrir el cofre")
    subparsers.add_parser("status", help="Ver el estado del cofre")

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup(args)
    elif args.command == "unlock":
        cmd_unlock(args)
    elif args.command == "status":
        cmd_status(args)

if __name__ == "__main__":
    main()