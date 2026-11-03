from getpass import getpass
from pathlib import Path

from rlyeh_crypto import MAGIC, HEADER_SIZE
from rlyeh_vault import seal_path, open_container


# Banner principal de Seal Of R'lyeh.
TITLE = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣤⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣽⣿⣿⡆
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⡿⠏⠉⠁
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣿⡟⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⢴⠛⢿⡿⠂⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢴⣪⡇⣿⠔⠁⠀⠀⠀⠀⠀⠀
⢀⡀⠀⠀⠀⠀⠀⠀⠀⣀⣀⠠⡤⢐⢨⣥⢮⠥⢛⠝⠉⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠙⠫⢍⣛⠉⠀⢉⣹⠣⠰⠖⠷⢚⣉⠥⠄⠊⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠈⠉⠁⠀⠓⠒⠀⠀⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

       ░▒▓█  S̷E̸A̴L̷  O̸F̷  R̴'̷L̸Y̷E̴H̷  █▓▒░

             ⛧  T H E  S U N K E N  S E A L  ⛧
                  ░░▒▒▓▓ RLYEH 01 ▓▓▒▒░░

"""


def ask_path(prompt):
    # Limpia la ruta ingresada y permite usar rutas relativas al usuario.
    value = input(prompt).strip().strip('"')

    if not value:
        raise ValueError("No se indicó ninguna ruta.")

    return Path(value).expanduser()


def seal():
    # Solicita las rutas de origen y destino.
    source = ask_path("Archivo o carpeta que sellar: ")
    destination = ask_path("Ruta del contenedor .rlyeh: ")

    # Los contenedores del proyecto utilizan la extensión .rlyeh.
    if destination.suffix.lower() != ".rlyeh":
        raise ValueError("El contenedor debe terminar en .rlyeh.")

    # getpass evita mostrar la contraseña mientras se escribe.
    password = getpass("Contraseña maestra: ")
    confirmation = getpass("Repite la contraseña: ")

    if password != confirmation:
        raise ValueError("Las contraseñas no coinciden.")

    if not password:
        raise ValueError("La contraseña no puede estar vacía.")

    # Delegamos el proceso de cifrado y empaquetado al módulo Vault.
    seal_path(source, destination, password)

    print("\n[OK] El sello se ha creado.")
    print("[INFO] El archivo original se conserva.")


def open_vault():
    # Solicita el contenedor que se desea abrir y la carpeta de recuperación.
    container = ask_path("Ruta del contenedor .rlyeh: ")
    destination = ask_path("Carpeta nueva para recuperar los datos: ")
    password = getpass("Contraseña maestra: ")

    # Vault se encarga de descifrar y recuperar el contenido.
    open_container(container, destination, password)

    print("\n[OK] Contenido recuperado correctamente.")


def inspect():
    path = ask_path("Ruta del contenedor: ")

    if not path.is_file():
        raise FileNotFoundError("No se encontró ese archivo.")

    # Leemos únicamente la cabecera para reconocer el formato.
    with path.open("rb") as file:
        header = file.read(HEADER_SIZE)

    # Comprobamos que la cabecera esté completa y tenga la firma esperada.
    if len(header) < HEADER_SIZE or not header.startswith(MAGIC):
        raise ValueError("No parece un contenedor RLYEH válido.")

    # Esta inspección no descifra ni verifica la integridad del contenido.
    print("\n--- REGISTRO DEL SELLO ---")
    print("Formato: RLYEH01")
    print(f"Tamaño: {path.stat().st_size:,} bytes")
    print("Estado: cabecera reconocida")
    print("Contenido y nombres internos: cifrados")
    print("Nota: esto no verifica la contraseña ni todo el contenido.")


def main():
    # Mantiene el menú activo hasta que el usuario decida salir.
    while True:
        print(TITLE)
        print("  [1] Sellar archivo o carpeta")
        print("  [2] Abrir contenedor")
        print("  [3] Inspeccionar contenedor")
        print("  [4] Abandonar el ritual")

        choice = input("\nElige una opción: ").strip()

        if choice == "4":
            print("El sello permanece. Hasta la próxima.")
            break

        # Relaciona cada opción del menú con su función correspondiente.
        actions = {
            "1": seal,
            "2": open_vault,
            "3": inspect,
        }

        action = actions.get(choice)

        if action is None:
            print("\n[!] Opción desconocida.")
            continue

        # Captura errores para evitar que una operación fallida cierre el menú.
        try:
            action()

        except (OSError, ValueError, zipfile_error()) as exc:
            print(f"\n[ERROR] {exc}")

        except KeyboardInterrupt:
            print("\n[!] Operación interrumpida.")

        except Exception as exc:
            # Último recurso para mostrar errores no contemplados.
            print(f"\n[ERROR INESPERADO] {exc}")

        input("\nPulsa Enter para volver al menú...")
        print("\n" * 2)


def zipfile_error():
    # Devuelve la excepción de ZIP para incluirla en el bloque de manejo de errores.
    import zipfile
    return zipfile.BadZipFile


# Ejecuta el menú solamente cuando este archivo se inicia directamente.
if __name__ == "__main__":
    main()