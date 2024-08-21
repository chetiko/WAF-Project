<?php

class HTTPConnectionFloodAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar la cantidad de conexiones activas y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';

        // Monitorea el número de conexiones activas desde la misma IP
        if ($this->isConnectionFlooding($ip)) {
            return true; // Se detecta un ataque HTTP Connection Flood
        }

        // Verifica si la conexión ha estado abierta demasiado tiempo sin actividad
        if ($this->isConnectionTooLong($ip)) {
            return true; // Conexión sospechosa detectada
        }

        // Detecta si hay un patrón de solicitudes incompletas
        if ($this->isRequestIncomplete($request)) {
            return true; // Solicitud incompleta detectada
        }

        return false; // No se detectaron ataques HTTP Connection Flood
    }

    private function isConnectionFlooding($ip) {
        // Incrementa el contador de conexiones activas para esta IP en Redis
        $connectionCount = $this->redis->incr("connection_count:$ip");
        $this->redis->expire("connection_count:$ip", 60); // Expira en 1 minuto

        // Define un umbral para la cantidad de conexiones simultáneas permitidas por IP
        $threshold = 100; // Ajustable según la capacidad del servidor
        return $connectionCount > $threshold;
    }

    private function isConnectionTooLong($ip) {
        // Monitorea el tiempo de conexión
        $startTime = $this->redis->get("connection_start_time:$ip");

        if (!$startTime) {
            // Si no existe, es la primera solicitud, guarda el tiempo actual
            $this->redis->set("connection_start_time:$ip", time());
            $this->redis->expire("connection_start_time:$ip", 3600); // Expira en 1 hora
            return false;
        }

        $elapsedTime = time() - $startTime;

        // Considera sospechosa una conexión que dure más de un umbral específico
        $maxAllowedTime = 300; // 5 minutos, ajustable
        return $elapsedTime > $maxAllowedTime;
    }

    private function isRequestIncomplete($request) {
        // Verifica si la solicitud está incompleta o mal formada
        if (empty($request['HTTP_USER_AGENT']) || empty($request['REQUEST_METHOD'])) {
            return true; // Falta información esencial en la solicitud, podría ser un ataque
        }

        // Verifica si los datos de POST están presentes cuando se espera que lo estén
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST)) {
            return true; // La solicitud POST está incompleta
        }

        return false;
    }
}
