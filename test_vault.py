
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from rlyeh_crypto import encrypt_file
from rlyeh_vault import seal_path, open_container


class TestVault(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.source = self.root / "documentos"
        self.source.mkdir()

        (self.source / "nota.txt").write_text(
            "El sello de R'lyeh permanece cerrado.",
            encoding="utf-8",
        )

        (self.source / "subcarpeta").mkdir()

        (self.source / "subcarpeta" / "secreto.txt").write_text(
            "Nug-Soth",
            encoding="utf-8",
        )

        self.container = self.root / "prueba.rlyeh"
        self.recovered = self.root / "recuperado"
        self.rejected = self.root / "no_deberia_existir"

        self.password = "Prueba-Rlyeh-938!"

    def tearDown(self):
        self.temp.cleanup()

    def test_folder_is_sealed_and_original_is_preserved(self):
        seal_path(
            self.source,
            self.container,
            self.password,
        )

        self.assertTrue(self.source.exists())
        self.assertTrue(self.container.is_file())

    def test_wrong_password_is_rejected(self):
        seal_path(
            self.source,
            self.container,
            self.password,
        )

        with self.assertRaisesRegex(ValueError, "Contraseña incorrecta"):
            open_container(
                str(self.container),
                str(self.rejected),
                "contraseña-incorrecta",
            )

        self.assertFalse(self.rejected.exists())

    def test_files_and_subfolders_are_recovered(self):
        seal_path(
            self.source,
            self.container,
            self.password,
        )

        open_container(
            str(self.container),
            str(self.recovered),
            self.password,
        )

        recovered_note = (
            self.recovered / "documentos" / "nota.txt"
        )

        original_note = self.source / "nota.txt"

        recovered_secret = (
            self.recovered
            / "documentos"
            / "subcarpeta"
            / "secreto.txt"
        )

        self.assertEqual(
            recovered_note.read_text(encoding="utf-8"),
            original_note.read_text(encoding="utf-8"),
        )

        self.assertEqual(
            recovered_secret.read_text(encoding="utf-8"),
            "Nug-Soth",
        )

    def test_single_file_is_sealed_and_recovered(self):
        original_file = self.root / "individual.txt"
        container = self.root / "individual.rlyeh"
        output = self.root / "salida"

        original_content = "Un archivo individual bajo el sello."
        original_file.write_text(original_content, encoding="utf-8")

        seal_path(
            original_file,
            container,
            self.password,
        )

        self.assertTrue(original_file.exists())
        self.assertTrue(container.is_file())

        open_container(
            container,
            output,
            self.password,
        )

        recovered_file = output / "individual.txt"

        self.assertEqual(
            original_content,
            recovered_file.read_text(encoding="utf-8"),
        )

    def test_existing_destination_is_not_overwritten(self):
        self.container.write_bytes(b"CONTENIDO ORIGINAL")

        with self.assertRaises(FileExistsError):
            seal_path(
                self.source,
                self.container,
                self.password,
            )

        self.assertEqual(
            self.container.read_bytes(),
            b"CONTENIDO ORIGINAL",
        )

    def test_nonexistent_source_is_rejected(self):
        missing_source = self.root / "no_existe.txt"

        with self.assertRaisesRegex(
            ValueError,
            "El origen no existe",
        ):
            seal_path(
                missing_source,
                self.container,
                self.password,
            )

        self.assertFalse(self.container.exists())

    def test_path_traversal_is_rejected(self):
        malicious_zip = self.root / "malicioso.zip"
        malicious_container = self.root / "malicioso.rlyeh"

        escaped_file = self.root / "archivo_fuera.txt"
        output = self.root / "recuperacion_maliciosa"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr(
                "../archivo_fuera.txt",
                "Este archivo no debería extraerse.",
            )

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "ruta peligrosa",
        ):
            open_container(
                malicious_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())
        self.assertFalse(escaped_file.exists())

    def test_duplicate_zip_entries_are_rejected(self):
        malicious_zip = self.root / "duplicado.zip"
        malicious_container = self.root / "duplicado.rlyeh"
        output = self.root / "recuperacion_duplicada"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("nota.txt", "Primera versión")
            zf.writestr("nota.txt", "Segunda versión")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        with self.assertRaisesRegex(
            ValueError,
            "rutas duplicadas",
        ):
            open_container(
                malicious_container,
                output,
                self.password,
            )

        self.assertFalse(output.exists())

    def test_file_size_limit_is_enforced(self):
        malicious_zip = self.root / "grande.zip"
        malicious_container = self.root / "grande.rlyeh"
        output = self.root / "recuperacion_grande"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("archivo.txt", b"123456")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        # Reducimos el límite a 5 bytes solo durante esta prueba.
        with patch("rlyeh_vault.MAX_FILE_SIZE", 5):
            with self.assertRaisesRegex(
                ValueError,
                "Un archivo supera el límite permitido",
            ):
                open_container(
                    malicious_container,
                    output,
                    self.password,
                )

        self.assertFalse(output.exists())

    def test_total_size_limit_is_enforced(self):
        malicious_zip = self.root / "total_grande.zip"
        malicious_container = self.root / "total_grande.rlyeh"
        output = self.root / "recuperacion_total_grande"

        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("archivo1.txt", b"123")
            zf.writestr("archivo2.txt", b"456")

        encrypt_file(
            str(malicious_zip),
            str(malicious_container),
            self.password,
        )

        # Reducimos el límite total a 5 bytes solo durante esta prueba.
        with patch("rlyeh_vault.MAX_TOTAL_SIZE", 5):
            with self.assertRaisesRegex(
                ValueError,
                "El contenido supera el límite de extracción",
            ):
                open_container(
                    malicious_container,
                    output,
                    self.password,
                )

        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
