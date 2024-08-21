<?php

class HTTPSlowReadAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar el seguimiento de la velocidad de lectura y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';

        // Monitorea la velocidad de lectura de datos desde el servidor
        if ($this->isReadingDataTooSlowly($ip)) {
            return true; // Se detecta un ataque HTTP Slow Read
        }

        // Monitorea el tiempo de conexión y el progreso en la transmisión de datos
        if ($this->isConnectionTooLong($ip)) {
            return true; // Conexión sospechosa detectada
        }

        return false; // No se detectaron ataques HTTP Slow Read
    }

    private function isReadingDataTooSlowly($ip) {
        // Obtiene el timestamp del inicio de la solicitud desde Redis
        $startTime = $this->redis->get("read_start_time:$ip");

        if (!$startTime) {
            // Si no existe, es la primera solicitud, guarda el tiempo actual
            $this->redis->set("read_start_time:$ip", time());
            $this->redis->expire("read_start_time:$ip", 3600); // Expira en 1 hora
            return false; // Aún no hay suficiente información para determinar si es un ataque
        }

        $elapsedTime = time() - $startTime;

        // Define un umbral para la velocidad mínima de lectura de datos en bytes por segundo
        $minBytesPerSecond = 10; // Umbral ajustable
        $expectedBytesRead = $elapsedTime * $minBytesPerSecond;

        // Obtiene la cantidad real de bytes leídos desde la conexión
        $actualBytesRead = $this->getBytesReadFromConnection($ip);

        // Si se han leído menos bytes de los esperados, se sospecha de un ataque Slow Read
        return $actualBytesRead < $expectedBytesRead;
    }

    private function getBytesReadFromConnection($ip) {
        // Simula la lectura de bytes de la conexión (este código debe ser reemplazado con la implementación real)
        // Se podría usar la capa de transporte del servidor para rastrear el progreso real en la lectura de datos.
        // Aquí se usaría, por ejemplo, la información del socket para contar los bytes leídos.
        $bytesRead = $this->redis->get("bytes_read:$ip") ?? 0;

        // Supongamos que hemos leído 50 bytes en la última verificación
        $newBytesRead = $bytesRead + 50;

        // Actualizamos el valor en Redis
        $this->redis->set("bytes_read:$ip", $newBytesRead);

        return $newBytesRead;
    }

    private function isConnectionTooLong($ip) {
        // Monitorea el tiempo de conexión
        $startTime = $this->redis->get("read_start_time:$ip");

        if ($startTime) {
            $elapsedTime = time() - $startTime;

            // Considera sospechosa una conexión que dure más de un umbral específico
            $maxAllowedTime = 120; // 2 minutos, ajustable
            return $elapsedTime > $maxAllowedTime;
        }

        return false;
    }
}

