import hashlib
import os
import time
import argparse

DIRECTORIO = ""
BASELINE = ""

def calcular_hash(ruta_archivo):
    sha256_hash = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            for bloque in iter(lambda: f.read(4096), b""):
                sha256_hash.update(bloque)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"Error leyendo {ruta_archivo}: {e}")
        return None


def crear_baseline():
    print("---CREANDO BASELINE---")
    if not os.path.exists(DIRECTORIO):
        print(f"ERROR: El directorio {DIRECTORIO} no existe.")
        return

    with open(BASELINE, "w") as f:
        for root, dirs, files in os.walk(DIRECTORIO):
            for file in files:
                ruta_completa = os.path.join(root, file)
                hash_file = calcular_hash(ruta_completa)
                if hash_file:
                    f.write(f"{ruta_completa}|{hash_file}\n")
                    print(f"[+] Indexado: {ruta_completa}")
        print(f"Baseline creado en {BASELINE}")


def monitorizar():
    print("---INICIANDO MONITORIZACION---")

    diccionario_baseline = {}

    if not os.path.exists(DIRECTORIO):
        print(f"ERROR: El directorio {DIRECTORIO} no existe.")
        return
    
    with open(BASELINE, "r") as f:
        for linea in f:
            ruta, hash_original = linea.strip().split("|") 
            diccionario_baseline[ruta] = hash_original
    
    print("---MONITORIZANDO (Ctrl + C para finalizar)---")

    while True:
        time.sleep(1)

        archivos_actuales = []

        for root, dirs, files in os.walk(DIRECTORIO):
            for file in files:
                ruta_completa = os.path.join(root, file)
                archivos_actuales.append(ruta_completa)

                hash_actual = calcular_hash(ruta_completa)

                if ruta_completa not in diccionario_baseline:
                    print(f"[ALERTA] Archivo CREADO: {ruta_completa}")
                    diccionario_baseline[ruta_completa] = hash_actual
                else:
                    if diccionario_baseline[ruta_completa] != hash_actual:
                        print(f"[ALERTA] Archivo MODIFICADO: {ruta_completa}")
                        diccionario_baseline[ruta_completa] = hash_actual
        rutas_en_baseline = list(diccionario_baseline.keys())
        for ruta in rutas_en_baseline:
            if ruta not in archivos_actuales:
                print(f"[ALERTA] Archivo ELIMINADO: {ruta}")
                del diccionario_baseline[ruta]

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Vigilador de integridad")
    parser.add_argument("directorio", help="Directorio que se quiere vigilar")
    parser.add_argument("--baseline", help="El archivo de baseline que se quiere usar", required=True)

    args = parser.parse_args()

    DIRECTORIO = args.directorio
    BASELINE = args.baseline

    while True:

        print("--- FILE INTEGRITY MONITOR ---")
        print("A) Crear nuevo baseline.")
        print("B) Empezar a monitorizar.")

        opcion = input("Seleccione opcion ").upper()

        if opcion == "A":
            crear_baseline()
        elif opcion == "B":
            monitorizar()
        else:
            print("Opcion no valida.")
