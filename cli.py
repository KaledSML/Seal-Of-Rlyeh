from getpass import getpass
from pathlib import Path

from rlyeh_crypto import MAGIC, HEADER_SIZE
from rlyeh_vault import seal_path, open_container



TITLE = r"""
╔══════════════════════════════════════╗
║                                      ║
║       ⛧  SEAL OF R'LYEH  ⛧          ║
║                                      ║
║          ⌁ THE SUNKEN SEAL ⌁         ║
║                                      ║
╚══════════════════════════════════════╝
"""


def ask_path(prompt):
    value = input(prompt).strip().strip('"')
    if not value:
        raise ValueError("No se indicó ninguna ruta.")
    return Path(value).expanduser()


def seal():
    source = ask_path("Archivo o carpeta que sellar: ")
    destination = ask_path("Ruta del contenedor .rlyeh: ")

    if destination.suffix.lower() != ".rlyeh":
        raise ValueError("El contenedor debe terminar en .rlyeh.")

    password = getpass("Contraseña maestra: ")
    confirmation = getpass("Repite la contraseña: ")

    if password != confirmation:
        raise ValueError("Las contraseñas no coinciden.")
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")

    seal_path(source, destination, password)
    print("\n[OK] El sello se ha creado.")
    print("[INFO] El archivo original se conserva.")


def open_vault():
    container = ask_path("Ruta del contenedor .rlyeh: ")
    destination = ask_path("Carpeta nueva para recuperar los datos: ")
    password = getpass("Contraseña maestra: ")

    open_container(container, destination, password)
    print("\n[OK] Contenido recuperado correctamente.")


def inspect():
    path = ask_path("Ruta del contenedor: ")

    if not path.is_file():
        raise FileNotFoundError("No se encontró ese archivo.")

    with path.open("rb") as file:
        header = file.read(HEADER_SIZE)

    if len(header) < HEADER_SIZE or not header.startswith(MAGIC):
        raise ValueError("No parece un contenedor RLYEH válido.")

    print("\n--- REGISTRO DEL SELLO ---")
    print("Formato: RLYEH01")
    print(f"Tamaño: {path.stat().st_size:,} bytes")
    print("Estado: cabecera reconocida")
    print("Contenido y nombres internos: cifrados")
    print("Nota: esto no verifica la contraseña ni todo el contenido.")


def main():
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

        actions = {
            "1": seal,
            "2": open_vault,
            "3": inspect,
        }

        action = actions.get(choice)
        if action is None:
            print("\n[!] Opción desconocida.")
            continue

        try:
            action()
        except (OSError, ValueError, zipfile_error()) as exc:
            print(f"\n[ERROR] {exc}")
        except KeyboardInterrupt:
            print("\n[!] Operación interrumpida.")
        except Exception as exc:
            print(f"\n[ERROR INESPERADO] {exc}")

        input("\nPulsa Enter para volver al menú...")
        print("\n" * 2)


def zipfile_error():
    # Evita que un error normal del contenedor cierre el menú.
    import zipfile
    return zipfile.BadZipFile


if __name__ == "__main__":
    main()
