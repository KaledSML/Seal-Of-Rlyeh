
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

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

    # NUEVAS PRUEBAS

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


if __name__ == "__main__":
    unittest.main()
