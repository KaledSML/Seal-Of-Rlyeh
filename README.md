# ⛧ SEAL OF R’LYEH
### THE SUNKEN SEAL · RLYEH 01

*«Algunas cosas deberían permanecer selladas.»*

Una herramienta de línea de comandos desarrollada en Python para proteger archivos y carpetas mediante contenedores cifrados `.rlyeh`.

Inspirado en el horror cósmico de H. P. Lovecraft.

---

## I. · El propósito

Seal Of R’lyeh permite sellar archivos y directorios dentro de un contenedor protegido por contraseña, y recuperar su contenido cuando sea necesario.

Su objetivo es combinar criptografía, validación de archivos y una interfaz sencilla, dentro de un proyecto personal de aprendizaje.

## II. · Propiedades del sello

- **Cifrado:** AES-256-GCM mediante la biblioteca `cryptography`.
- **Derivación de claves:** Scrypt.
- **Contenedores:** formato propio `.rlyeh`.
- **Integridad:** detección de contraseñas incorrectas y contenido alterado.
- **Archivos y carpetas:** empaquetado y recuperación.
- **Validación:** controles de seguridad antes de extraer archivos ZIP.
- **Protección:** evita sobrescribir archivos y contenedores existentes.

## III. · Instrumentos utilizados

| Herramienta | Función |
|---|---|
| Python 3.15 | Lenguaje principal |
| `cryptography` | Operaciones criptográficas |
| ZIP | Organización interna del contenido |

## IV. · Preparación del ritual

Clona el repositorio:

```powershell
git clone https://github.com/KaledSML/Seal-Of-Rlyeh.git
cd Seal-Of-Rlyeh
```

Crea el entorno virtual e instala la dependencia:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install cryptography
```

## V. · Ejecución

Inicia la aplicación desde PowerShell:

```powershell
.\.venv\Scripts\python.exe .\cli.py
```

El menú permite realizar cuatro acciones:

1. Sellar un archivo o carpeta.
2. Abrir un contenedor.
3. Inspeccionar un contenedor.
4. Abandonar el ritual.

## VI. · Estructura interna

El proyecto se organiza en tres módulos:

| Módulo | Responsabilidad |
|---|---|
| `cli.py` | Interfaz y navegación |
| `rlyeh_vault.py` | Gestión de contenedores y validación ZIP |
| `rlyeh_crypto.py` | Derivación de claves y cifrado |

## VII. · Verificación

El proyecto dispone de **28 pruebas automatizadas** que comprueban el comportamiento criptográfico, la recuperación de archivos, la validación de contenedores y el manejo de errores.

**Última ejecución:** 28 pruebas superadas.

## VIII. · Advertencias

- Desarrollado para Windows y uso desde terminal.
- El cifrado y descifrado procesan los archivos completos en memoria.
- La inspección de cabecera no garantiza por sí sola que un contenedor sea íntegro o pueda abrirse correctamente.

## IX. · Registro de autoría

Proyecto personal de aprendizaje y desarrollo, inspirado en el universo literario de H. P. Lovecraft.

*Ph'nglui mglw'nafh R'lyeh wgah'nagl fhtagn.*

---

<sub>SEAL OF R’LYEH · RLYEH 01 · THE SUNKEN SEAL</sub>
