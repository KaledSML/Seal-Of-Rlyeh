
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from rlyeh_crypto import encrypt_file, decrypt_file


class TestCrypto(unittest.TestCase):

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)

        self.original = self.root / "mensaje.txt"
        self.container = self.root / "mensaje.rlyeh"
        self.recovered = self.root / "recuperado.txt"
        self.rejected = self.root / "no_deberia_existir.txt"

        self.password = "Clave-de-prueba-938!"

        self.original.write_text(
            "Ph'nglui mglw'nafh R'lyeh wgah'nagl fhtagn.",
            encoding="utf-8",
        )

        encrypt_file(
            str(self.original),
            str(self.container),
            self.password,
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_wrong_password_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Contraseña incorrecta"):
            decrypt_file(
                str(self.container),
                str(self.rejected),
                "Clave-incorrecta",
            )

        self.assertFalse(self.rejected.exists())

    def test_container_is_not_modified_after_wrong_password(self):
        before = self.container.read_bytes()

        with self.assertRaises(ValueError):
            decrypt_file(
                str(self.container),
                str(self.rejected),
                "Clave-incorrecta",
            )

        after = self.container.read_bytes()

        self.assertEqual(before, after)
        self.assertFalse(self.rejected.exists())

    def test_correct_password_recovers_original_file(self):
        decrypt_file(
            str(self.container),
            str(self.recovered),
            self.password,
        )

        self.assertEqual(
            self.original.read_bytes(),
            self.recovered.read_bytes(),
        )

    def test_existing_container_is_not_overwritten(self):
        before = self.container.read_bytes()

        with self.assertRaises(FileExistsError):
            encrypt_file(
                str(self.original),
                str(self.container),
                "Otra-clave-de-prueba",
            )

        self.assertEqual(before, self.container.read_bytes())

    def test_existing_output_file_is_not_overwritten(self):
        decrypt_file(
            str(self.container),
            str(self.recovered),
            self.password,
        )

        before = self.recovered.read_bytes()

        with self.assertRaises(FileExistsError):
            decrypt_file(
                str(self.container),
                str(self.recovered),
                self.password,
            )

        self.assertEqual(before, self.recovered.read_bytes())

    def test_altered_container_is_rejected(self):
        damaged = self.root / "alterado.rlyeh"

        damaged_data = bytearray(self.container.read_bytes())
        damaged_data[-1] ^= 1
        damaged.write_bytes(damaged_data)

        damaged_output = self.root / "salida_alterada.txt"

        with self.assertRaisesRegex(
            ValueError,
            "Contraseña incorrecta o contenedor alterado",
        ):
            decrypt_file(
                str(damaged),
                str(damaged_output),
                self.password,
            )

        self.assertFalse(damaged_output.exists())

    # NUEVAS PRUEBAS

    def test_empty_password_is_rejected(self):
        with self.assertRaisesRegex(
            ValueError,
            "La contraseña no puede estar vacía",
        ):
            encrypt_file(
                str(self.original),
                str(self.root / "sin_clave.rlyeh"),
                "",
            )

    def test_empty_file_is_recovered_correctly(self):
        empty_file = self.root / "vacio.txt"
        empty_container = self.root / "vacio.rlyeh"
        empty_recovered = self.root / "vacio_recuperado.txt"

        empty_file.write_bytes(b"")

        encrypt_file(
            str(empty_file),
            str(empty_container),
            self.password,
        )

        decrypt_file(
            str(empty_container),
            str(empty_recovered),
            self.password,
        )

        self.assertEqual(b"", empty_recovered.read_bytes())

    def test_binary_file_is_recovered_exactly(self):
        binary_file = self.root / "datos.bin"
        binary_container = self.root / "datos.rlyeh"
        binary_recovered = self.root / "datos_recuperados.bin"

        original_data = bytes(range(256)) + b"\x00\xFF\xFE"
        binary_file.write_bytes(original_data)

        encrypt_file(
            str(binary_file),
            str(binary_container),
            self.password,
        )

        decrypt_file(
            str(binary_container),
            str(binary_recovered),
            self.password,
        )

        self.assertEqual(
            original_data,
            binary_recovered.read_bytes(),
        )

    def test_invalid_header_is_rejected(self):
        invalid_container = self.root / "invalido.rlyeh"
        invalid_container.write_bytes(b"XXXXXXXX" + b"\x00" * 44)

        invalid_output = self.root / "salida_invalida.txt"

        with self.assertRaisesRegex(
            ValueError,
            "no es un contenedor RLYEH compatible",
        ):
            decrypt_file(
                str(invalid_container),
                str(invalid_output),
                self.password,
            )

        self.assertFalse(invalid_output.exists())


if __name__ == "__main__":
    unittest.main()
