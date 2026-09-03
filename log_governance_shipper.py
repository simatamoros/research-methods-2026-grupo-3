INICIO PROCEDIMIENTO ValidacionGobernanzaOrigen(L_raw, S_req)

    PARA CADA registro r EN L_raw HACER:
        
        // Paso 1: Decodificación y verificación de integridad estructural
        INTENTAR:
            evento_json ← ParsearJSON(r)
        EXCEPTUAR ErrorSintactico:
            EnrutarAislamiento(r, "ERR_CORRUPT_JSON_SYNTAX")
            CONTINUAR
            
        // Paso 2: Auditoría de completitud de esquema mandatorio
        esquema_valido ← VERDADERO
        PARA CADA campo c EN S_req HACER:
            SI (c NO ESTÁ EN evento_json) O (evento_json[c] ES NULO) O (Longitud(evento_json[c]) == 0) ENTONCES:
                esquema_valido ← FALSO
                EnrutarAislamiento(r, Concatenar("SCHEMA_VIOLATION_MISSING_", c))
                ROMPER BUCLE
            FIN SI
        FIN PARA
        
        SI esquema_valido == FALSO ENTONCES:
            CONTINUAR
        FIN SI
        
        // Paso 3: Verificación de consistencia temporal ISO 8601
        SI NO EsFormatoISO8601Valido(evento_json["@timestamp"]) ENTONCES:
            EnrutarAislamiento(r, "ERR_INVALID_TIMESTAMP_FORMAT")
            CONTINUAR
        FIN SI
        
        // Paso 4: Certificación sintáctica Zero Trust e inyección de metadatos
        evento_json["governance_status"] ← "CERTIFIED_ZERO_TRUST"
        evento_json["schema_version"] ← "1.0-HN"
        
        // Paso 5: Emisión de telemetría purificada al pipeline del SIEM
        EmitirSalidaEstandar(ConvertirAJSON(evento_json))
        
    FIN PARA

FIN PROCEDIMIENTO