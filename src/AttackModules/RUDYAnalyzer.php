<?php

class RUDYAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar la tasa de solicitudes y almacenar información temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'];
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 0;

        // Verifica si la solicitud es un POST con un tamaño de contenido significativo
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $contentLength > 0) {
            // Verifica si los datos POST se están enviando demasiado lentamente
            if ($this->isSendingDataTooSlowly($ip, $contentLength)) {
                return true; // Se detecta un ataque RUDY
            }
        }

        return false;
    }

    private function isSendingDataTooSlowly($ip, $contentLength) {
        // Obtiene el timestamp del inicio de la solicitud desde Redis
        $startTime = $this->redis->get("request_start_time:$ip");
        
        if (!$startTime) {
            // Si no existe, es la primera solicitud, así que guarda el tiempo actual
            $this->redis->set("request_start_time:$ip", time());
            $this->redis->expire("request_start_time:$ip", 3600); // Expira en 1 hora
            return false; // Aún no hay suficiente información para determinar si es un ataque
        }

        $elapsedTime = time() - $startTime;
        
        // Define un umbral para la velocidad mínima de transmisión de datos en bytes por segundo
        $minBytesPerSecond = 10; // Ejemplo de umbral, ajustar según sea necesario
        $expectedBytesSent = $elapsedTime * $minBytesPerSecond;

        // Si se han enviado menos bytes de los esperados, se sospecha de un ataque RUDY
        if ($contentLength < $expectedBytesSent) {
            return true;
        }

        return false;
    }
}

