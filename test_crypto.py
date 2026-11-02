from pathlib import Path
from tempfile import TemporaryDirectory
from hashlib import sha256

from rlyeh_crypto import encrypt_file, decrypt_file

with TemporaryDirectory() as temp:
    root = Path(temp)
    original = root / "mensaje.txt"
    container = root / "mensaje.rlyeh"
    recovered = root / "recuperado.txt"
    rejected = root / "no_deberia_existir.txt"

    original.write_text(
        "Ph'nglui mglw'nafh R'lyeh wgah'nagl fhtagn.",
        encoding="utf-8",
    )

    encrypt_file(str(original), str(container), "Clave-de-prueba-938!")
    before = sha256(container.read_bytes()).hexdigest()

    try:
        decrypt_file(str(container), str(rejected), "Clave-incorrecta")
        raise AssertionError("ERROR: se aceptó una contraseña incorrecta.")
    except ValueError as exc:
        if "Contraseña incorrecta" not in str(exc):
            raise
        print("OK: contraseña incorrecta rechazada.")

    after = sha256(container.read_bytes()).hexdigest()
    assert before == after, "ERROR: el contenedor fue alterado."
    assert not rejected.exists(), "ERROR: se creó una salida no autorizada."
    print("OK: contenedor intacto y sin archivo de salida indebido.")

    decrypt_file(str(container), str(recovered), "Clave-de-prueba-938!")
    assert recovered.read_bytes() == original.read_bytes()
    print("OK: recuperación exacta con la contraseña correcta.")


    # Prueba 1: no sobrescribir un contenedor existente.
    container_before = container.read_bytes()

    try:
        encrypt_file(
            str(original),
            str(container),
            "Otra-clave-de-prueba",
        )
        raise AssertionError(
            "ERROR: se sobrescribió un contenedor existente."
        )
    except FileExistsError:
        print("OK: no se sobrescribe un contenedor existente.")

    assert container.read_bytes() == container_before

    # Prueba 2: no sobrescribir un archivo recuperado existente.
    recovered_before = recovered.read_bytes()

    try:
        decrypt_file(
            str(container),
            str(recovered),
            "Clave-de-prueba-938!",
        )
        raise AssertionError(
            "ERROR: se sobrescribió un archivo existente."
        )
    except FileExistsError:
        print("OK: no se sobrescribe un archivo existente.")

    assert recovered.read_bytes() == recovered_before

    # Prueba 3: rechazar un contenedor alterado.
    damaged = root / "alterado.rlyeh"
    damaged_data = bytearray(container.read_bytes())
    damaged_data[-1] ^= 1
    damaged.write_bytes(damaged_data)

    damaged_output = root / "salida_alterada.txt"

    try:
        decrypt_file(
            str(damaged),
            str(damaged_output),
            "Clave-de-prueba-938!",
        )
        raise AssertionError(
            "ERROR: se aceptó un contenedor alterado."
        )

    except ValueError as exc:
        if "Contraseña incorrecta o contenedor alterado" not in str(exc):
            raise
        print("OK: contenedor alterado rechazado.")


    assert not damaged_output.exists()


print("TODAS LAS PRUEBAS SUPERADAS.")
