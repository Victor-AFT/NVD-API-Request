
# 🛡️ NVD-API-Request — Consultas a la National Vulnerability Database (NVD)

Este repositorio contiene scripts y ejemplos para **consultar la API 2.0 de la NVD (NIST)** y trabajar con CVE/CPE desde Python y/o cURL. Está pensado para tareas de **threat intel**, **inventariado de vulnerabilidades** y **automatización** en pipelines de seguridad.

> La API pública de la NVD expone datos JSON con paginación, filtros por fechas, CPE, severidad CVSS y más. Para volúmenes altos, solicita una **API Key** gratuita. citeturn9search35turn9search28

---
## 🚀 Funcionalidades (del repositorio)
- Ejemplos de **búsqueda de CVE** por palabra clave, CPE y rangos de fechas. citeturn9search35
- Soporte para **API Key** y manejo básico de **rate limiting** recomendado por NVD. citeturn9search28turn9search35
- Descarga de resultados y exportación a **JSON/CSV** (scripts de ejemplo).
- Snippets con **cURL** y **Python `requests`**.

> Alternativamente, puedes usar librerías de terceros como **nvdlib** (wrapper de NVD API 2.0) si prefieres objetos Python listos para usar. citeturn9search29

---
## 📦 Requisitos
- **Python 3.9+**
- Dependencias mínimas:

```bash
pip install requests python-dateutil
```

> Si precisas un cliente listo, considera `nvd-api` (cliente 2.0 de la comunidad) o `nvdlib`. citeturn9search31turn9search29

---
## 🔑 API Key (opcional pero recomendado)
- Solicita una API Key gratuita en la página oficial de NVD y actívala desde el email que recibirás. citeturn9search28
- La API sin key está sujeta a límites públicos; con key, los límites aumentan. (Consulta *Developers* en la doc). citeturn9search35

Configura tu key en una variable de entorno:
```bash
export NVD_API_KEY="TU_API_KEY"
```

---
## ▶️ Ejemplos de uso

### 1) cURL — Búsqueda por palabra clave
```bash
curl -s   "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=openssl&resultsPerPage=20"   -H "Accept: application/json"
```
> Endpoint base y parámetros oficiales de la API 2.0 (CVE). citeturn9search35

### 2) Python — Búsqueda por CPE y filtrado por fechas
```python
import os, requests
from datetime import datetime, timedelta

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")
headers = {"Accept": "application/json"}
if API_KEY:
    headers["apiKey"] = API_KEY

params = {
    # CPE v2.3 de ejemplo (ajústalo a tu inventario)
    "cpeName": "cpe:2.3:o:debian:debian_linux:11:*:*:*:*:*:*:*",
    # Rango de publicación de 30 días
    "pubStartDate": (datetime.utcnow()-timedelta(days=30)).isoformat(timespec="seconds")+".000",
    "pubEndDate": datetime.utcnow().isoformat(timespec="seconds")+".000",
    "resultsPerPage": 200,
    "startIndex": 0
}

r = requests.get(API_URL, headers=headers, params=params, timeout=60)
r.raise_for_status()
data = r.json()
print("CVE totales:", data.get("totalResults"))
```
> La API usa paginación (`resultsPerPage`, `startIndex`) y límites de rango de fechas; revisa restricciones y mejores prácticas en la doc oficial. citeturn9search35

### 3) Python — Búsqueda por ID de CVE
```python
import requests
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {"cveId": "CVE-2024-30078"}
print(requests.get(API_URL, params=params, timeout=60).json())
```
> El endpoint CVE 2.0 permite consultar por `cveId` directamente. citeturn9search35

---
## 🧭 Buenas prácticas con la API de la NVD
- Pagina los resultados con `resultsPerPage` y `startIndex`. citeturn9search35
- Respeta las **ventanas máximas de fecha** y limita el tamaño de respuesta. (p. ej., 120 días para ciertos filtros en clientes de la comunidad). citeturn9search31turn9search34
- Usa **API Key** para mayores umbrales de consulta. citeturn9search28
- Considera **backoff**/esperas en bucles de paginación.

---
## 🗂️ Estructura sugerida del repo
```
NVD-API-Request/
├── src/
│   ├── nvd_query.py           # Funciones para queries genéricas
│   ├── export_utils.py        # Exportación JSON/CSV
│   └── examples/
│       ├── by_keyword.py
│       ├── by_cpe_and_dates.py
│       └── by_cve_id.py
├── data/                      # Resultados (gitignored si contiene datos grandes)
├── requirements.txt
└── README.md
```

---
## 📤 Exportación de resultados (ejemplo)
```python
import csv

def export_to_csv(vulnerabilities, path):
    fields = ["id", "published", "lastModified", "cvss", "severity", "cwes"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(fields)
        for v in vulnerabilities:
            writer.writerow([
                v.get("cve", {}).get("id"),
                v.get("cve", {}).get("published"),
                v.get("cve", {}).get("lastModified"),
                # Extrae tus métricas CVSS v2/v3 según el esquema de la respuesta 2.0
                None, None, None,
            ])
```
> La respuesta 2.0 incluye `vulnerabilities` con metadatos CVE y métricas CVSS; estructura oficial en *Developers > Vulnerabilities*. citeturn9search35

---
## 📚 Referencias
- **NVD Developers — Vulnerabilities (API 2.0)**: conceptos, paginación y esquema de respuesta. citeturn9search35
- **Pedir API Key** (NVD). citeturn9search28
- **Clientes/librerías de comunidad (opcional)**: `nvdlib`, `nvd-api`. citeturn9search29turn9search31

---
## 📝 Licencia
Indica aquí la licencia elegida (p. ej., MIT/Apache-2.0).
