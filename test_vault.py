from pathlib import Path
from tempfile import TemporaryDirectory

from rlyeh_vault import seal_path, open_container

with TemporaryDirectory() as temp:
    root = Path(temp)
    source = root / "documentos"
    source.mkdir()
    (source / "nota.txt").write_text(
        "El sello de R'lyeh permanece cerrado.",
        encoding="utf-8",
    )
    (source / "subcarpeta").mkdir()
    (source / "subcarpeta" / "secreto.txt").write_text(
        "Nug-Soth", encoding="utf-8"
    )

    container = root / "prueba.rlyeh"
    recovered = root / "recuperado"
    rejected = root / "no_deberia_existir"

    seal_path(source, container, "Prueba-Rlyeh-938!")

    assert source.exists()
    assert container.is_file()
    print("OK: carpeta sellada y original conservado.")

    try:
        open_container(
            str(container), str(rejected), "contraseña-incorrecta"
        )
        raise AssertionError("Se aceptó una contraseña incorrecta.")
    except ValueError as exc:
        if "Contraseña incorrecta" not in str(exc):
            raise

    assert not rejected.exists()
    print("OK: contraseña incorrecta rechazada.")

    open_container(
        str(container), str(recovered), "Prueba-Rlyeh-938!"
    )

    assert (
        recovered / "documentos" / "nota.txt"
    ).read_text(encoding="utf-8") == (
        source / "nota.txt"
    ).read_text(encoding="utf-8")

    assert (
        recovered / "documentos" / "subcarpeta" / "secreto.txt"
    ).read_text(encoding="utf-8") == "Nug-Soth"

    print("OK: archivos y subcarpetas recuperados.")
    print("TODAS LAS PRUEBAS SUPERADAS.")
