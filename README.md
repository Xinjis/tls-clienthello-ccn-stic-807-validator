# TLS ClientHello CCN-STIC-807 Validator

Script en Bash para analizar exportes de Client Hello (Wireshark/TShark) y detectar evidencia de no conformidad con CCN-STIC-807 cuando se ofrecen cipher suites o grupos clasificados como Legacy o Not Recommended.

## What it does
- Analiza uno o varios archivos `.txt`
- Detecta cipher suites TLS prohibidas del listado evaluado
- Detecta grupos Legacy evaluados
- Devuelve PASS/FAIL por archivo y resultado global
- Enfoca el resultado como evidencia de conformidad/no conformidad con CCN-STIC-807

## Scope
Este script valida evidencia textual exportada de Wireshark/TShark.
No sustituye una evaluación criptográfica integral ni acredita cumplimiento total por sí solo.

## Use case
Validación de evidencias de tráfico TLS hacia endpoints de validación de licencia, por ejemplo:
- cloud.gluu.org
- account.gluu.org

## Requirements
- Bash
- grep
- sed
- sort

## Usage
```bash
chmod +x check_tls.sh
./check_tls.sh archivo1.txt
./check_tls.sh archivo1.txt archivo2.txt archivo3.txt
./check_tls.sh *.txt

Example output: [RESULTADO][sample_fail.txt] FAIL
  Evidencia de NO conformidad con CCN-STIC-807.

Methodology

El script busca suites y grupos definidos en listas internas del script como:
	•	Legacy
	•	Not Recommended
	•	Legacy groups

Limitations
	•	Depende de la calidad de la exportación textual
	•	No analiza PCAP directamente
	•	No reemplaza revisión manual ni contraste con la versión vigente del estándar
