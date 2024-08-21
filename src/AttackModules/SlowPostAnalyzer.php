<?php

class SlowPostAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar la tasa de transmisión de datos y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 0;

        // Verifica si la solicitud es un POST con un tamaño de contenido significativo
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $contentLength > 0) {
            // Verifica la velocidad de envío de datos
            if ($this->isSendingDataTooSlowly($ip, $contentLength)) {
                return true; // Se detecta un ataque Slow POST
            }

            // Verifica si la conexión ha estado abierta demasiado tiempo
            if ($this->isConnectionTooLong($ip)) {
                return true; // Conexión sospechosa detectada
            }
        }

        return false; // No se detectaron ataques Slow POST
    }

    private function isSendingDataTooSlowly($ip, $contentLength) {
        // Obtiene el timestamp del inicio de la solicitud desde Redis
        $startTime = $this->redis->get("post_start_time:$ip");
        
        if (!$startTime) {
            // Si no existe, es la primera solicitud, guarda el tiempo actual
            $this->redis->set("post_start_time:$ip", time());
            $this->redis->expire("post_start_time:$ip", 3600); // Expira en 1 hora
            return false; // Aún no hay suficiente información para determinar si es un ataque
        }

        $elapsedTime = time() - $startTime;
        
        // Define un umbral para la velocidad mínima de transmisión de datos en bytes por segundo
        $minBytesPerSecond = 10; // Umbral ajustable
        $expectedBytesSent = $elapsedTime * $minBytesPerSecond;

        // Si se han enviado menos bytes de los esperados, se sospecha de un ataque Slow POST
        return $contentLength < $expectedBytesSent;
    }

    private function isConnectionTooLong($ip) {
        // Monitorea el tiempo de conexión
        $startTime = $this->redis->get("post_start_time:$ip");

        if ($startTime) {
            $elapsedTime = time() - $startTime;

            // Considera sospechosa una conexión que dure más de un umbral específico
            $maxAllowedTime = 120; // 2 minutos, ajustable
            return $elapsedTime > $maxAllowedTime;
        }

        return false;
    }
}

