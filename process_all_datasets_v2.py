import json
import glob
import hashlib
import os
import tarfile
import zipfile
import xmltodict
import Evtx.Evtx as evtx

OUTPUT_FILE = "/var/log/simulated_attack.log"
TARGET_EVENTS = 2000  # 1000 de Mordor + 1000 de EVTX-Samples

seen_signatures = set()
unique_count = 0

print("=" * 70)
print("[*] INICIANDO PROCESAMIENTO: Mordor + EVTX (Filtro por Campos Clave)")
print("=" * 70)

def flatten_eventdata(obj):
    """Convierte listas de Data Name/Value de Windows en claves directas."""
    if isinstance(obj, dict) and "Event" in obj:
        ed = obj["Event"].get("EventData", {})
        if isinstance(ed, dict) and "Data" in ed:
            data_items = ed["Data"]
            if isinstance(data_items, list):
                flat = {}
                for item in data_items:
                    if isinstance(item, dict) and "@Name" in item:
                        flat[item["@Name"]] = item.get("#text", "")
                obj["Event"]["EventData"] = flat
    return obj

def get_event_fingerprint(obj, source_file=""):
    """
    Extrae los campos únicos (EventRecordID, Computer, ProcessGuid, Timestamp) 
    para crear una firma única garantizada forensemente.
    """
    sys_node = obj.get("Event", {}).get("System", {}) if isinstance(obj, dict) else {}
    ed_node = obj.get("Event", {}).get("EventData", {}) if isinstance(obj, dict) else {}
    
    # 1. Extraer identificadores secuenciales
    record_id = sys_node.get("EventRecordID") or obj.get("record_number") or ""
    
    # 2. Extraer Host / Máquina
    computer = sys_node.get("Computer") or obj.get("hostname") or obj.get("ComputerName") or ""
    
    # 3. Extraer GUID de Sysmon (si existe)
    guid = ed_node.get("ProcessGuid") or obj.get("ProcessGuid") or ""
    
    # 4. Extraer Timestamp
    time_created = ""
    tc_node = sys_node.get("TimeCreated")
    if isinstance(tc_node, dict):
        time_created = tc_node.get("@SystemTime", "")
    else:
        time_created = ed_node.get("UtcTime") or obj.get("@timestamp") or ""
        
    dataset_src = obj.get("dataset_source", "")
    file_origin = obj.get("technique_file", source_file)
    
    # Crear la firma concatenando los campos críticos
    signature_string = f"{dataset_src}|{file_origin}|{computer}|{record_id}|{guid}|{time_created}"
    
    # Si por alguna razón el evento no tiene campos estándar de Windows, 
    # usar el hash completo del JSON como mecanismo de rescate (fallback).
    if signature_string == "|||||":
        return hashlib.sha256(json.dumps(obj, sort_keys=True).encode("utf-8")).hexdigest()
        
    return hashlib.sha256(signature_string.encode("utf-8")).hexdigest()

# Limpiar archivo de logs previo
open(OUTPUT_FILE, "w").close()

with open(OUTPUT_FILE, "a", encoding="utf-8") as out:

    # -------------------------------------------------------------
    # 1. PROCESAR MORDOR (Security-Datasets)
    # -------------------------------------------------------------
    print("[+] [1/2] Extrayendo eventos desde Mordor...")
    mordor_path = "/opt/threat-datasets/mordor"
    mordor_archives = glob.glob(f"{mordor_path}/**/*.tar.gz", recursive=True) + \
                      glob.glob(f"{mordor_path}/**/*.zip", recursive=True) + \
                      glob.glob(f"{mordor_path}/**/*.json", recursive=True)

    mordor_count = 0
    for arch in mordor_archives:
        if mordor_count >= 1000:
            break
        try:
            if arch.endswith(".tar.gz"):
                with tarfile.open(arch, "r:gz") as tar:
                    for member in tar.getmembers():
                        if member.name.endswith(".json") or member.name.endswith(".log"):
                            f = tar.extractfile(member)
                            if f:
                                for line in f:
                                    if mordor_count >= 1000: break
                                    try:
                                        data = json.loads(line.decode("utf-8", errors="ignore"))
                                        clean = flatten_eventdata(data)
                                        clean["dataset_source"] = "Mordor_Security_Datasets"
                                        
                                        # Aplicar nueva lógica de unicidad
                                        fingerprint = get_event_fingerprint(clean, os.path.basename(arch))
                                        
                                        if fingerprint not in seen_signatures:
                                            seen_signatures.add(fingerprint)
                                            out.write(json.dumps(clean, sort_keys=True) + "\n")
                                            mordor_count += 1
                                            unique_count += 1
                                    except Exception: continue

            elif arch.endswith(".json"):
                with open(arch, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if mordor_count >= 1000: break
                        try:
                            data = json.loads(line)
                            clean = flatten_eventdata(data)
                            clean["dataset_source"] = "Mordor_Security_Datasets"
                            
                            # Aplicar nueva lógica de unicidad
                            fingerprint = get_event_fingerprint(clean, os.path.basename(arch))
                            
                            if fingerprint not in seen_signatures:
                                seen_signatures.add(fingerprint)
                                out.write(json.dumps(clean, sort_keys=True) + "\n")
                                mordor_count += 1
                                unique_count += 1
                        except Exception: continue
        except Exception: continue

    print(f"[✓] Eventos únicos de Mordor: {mordor_count}")

    # -------------------------------------------------------------
    # 2. PROCESAR EVTX-ATTACK-SAMPLES (.evtx)
    # -------------------------------------------------------------
    print("[+] [2/2] Convirtiendo binarios de EVTX-ATTACK-SAMPLES...")
    evtx_path = "/opt/threat-datasets/evtx-samples"
    evtx_files = glob.glob(f"{evtx_path}/**/*.evtx", recursive=True)

    evtx_count = 0
    for file_path in evtx_files:
        if evtx_count >= 1000:
            break
        try:
            with evtx.Evtx(file_path) as log:
                for record in log.records():
                    if evtx_count >= 1000: break
                    try:
                        xml_content = record.xml()
                        parsed = xmltodict.parse(xml_content)
                        clean = flatten_eventdata(parsed)
                        clean["dataset_source"] = "EVTX_ATTACK_SAMPLES"
                        clean["technique_file"] = os.path.basename(file_path)

                        # Aplicar nueva lógica de unicidad para EVTX
                        fingerprint = get_event_fingerprint(clean, os.path.basename(file_path))
                        
                        if fingerprint not in seen_signatures:
                            seen_signatures.add(fingerprint)
                            out.write(json.dumps(clean, sort_keys=True) + "\n")
                            evtx_count += 1
                            unique_count += 1
                    except Exception: continue
        except Exception: continue

    print(f"[✓] Eventos únicos de EVTX: {evtx_count}")

print("=" * 70)
print(f"[+] PROCESO COMPLETADO: {unique_count} eventos inyectados con filtrado de claves Windows.")
print(f"[+] Archivo destino: {OUTPUT_FILE}")
print("=" * 70)
