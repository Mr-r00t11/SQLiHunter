# SQLiHunter

## Descripción

SQLiHunter es una herramienta automatizada para detectar y explotar vulnerabilidades de inyección SQL en aplicaciones web. Utiliza payloads específicos para diferentes gestores de bases de datos y permite identificar vulnerabilidades tanto por errores visibles como por técnicas blind. Además, ofrece la opción de intentar explotar las vulnerabilidades detectadas utilizando `sqlmap`.

## Funcionalidades

- Detecta vulnerabilidades SQLi basadas en errores.
- Detecta vulnerabilidades SQLi blind.
- Guarda los resultados en archivos CSV, TXT y HTML con un diseño atractivo.
- Opción de explotar las vulnerabilidades detectadas utilizando `sqlmap`.

## Requisitos

- Python 3.x
- `requests` library: `pip install requests`
- `colorama` library: `pip install colorama`
- `sqlmap`: [Instalación de sqlmap](https://github.com/sqlmapproject/sqlmap)

## Instalación

1. Clona el repositorio:
```bash
git clone https://github.com/tu_usuario/tu_repositorio.git
```

2. Navega al directorio del proyecto:
```bash
cd SQLiHunter
```

3. Instala las dependencias:
```bash
pip install -r requirements.txt
```

## Uso

1. Prepara un archivo de texto con las URLs que deseas analizar. Cada URL debe estar en una línea separada.
  
2. Ejecuta el script de detección:
```bash
python SQLiHunter.py urls.txt
```

- Donde `urls.txt` es el archivo que contiene las URLs a analizar.

3. Al finalizar la ejecución, el script generará tres archivos con los resultados:
    
    - `vulnerable_urls.csv`: Contiene las URLs vulnerables en formato CSV.
    - `vulnerable_urls.txt`: Contiene las URLs vulnerables en formato de texto plano.
    - `vulnerable_urls.html`: Contiene las URLs vulnerables en formato HTML con un diseño atractivo.
4. El script te preguntará si deseas intentar explotar las vulnerabilidades detectadas utilizando `sqlmap`. Si respondes "s", se ejecutará `sqlmap` en cada URL y parámetro vulnerable detectado.

## Ejemplo

Archivo `urls.txt`:
```bash
http://example.com/page?param1=value1&param2=value2
http://example.org/search?query=test
```

Ejecutar el script:
```bash
python SQLiHunter.py urls.txt
```

Resultados generados:
- `vulnerable_urls.csv`
- `vulnerable_urls.txt`
- `vulnerable_urls.html`

## Notas

- Asegúrate de tener permiso para realizar pruebas de seguridad en las URLs que analices.
- El uso de `sqlmap` debe realizarse con responsabilidad y siempre bajo el consentimiento del propietario del sitio web.
