<?php

class RateLimiter {

    private $redis;
    private $requestLimit;
    private $timeWindow;

    public function __construct($requestLimit = 100, $timeWindow = 60) {
        // Conectar a Redis para manejar el conteo de solicitudes
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);

        // Configuraciones de limitación de tasa
        $this->requestLimit = $requestLimit; // Número máximo de solicitudes permitidas
        $this->timeWindow = $timeWindow; // Ventana de tiempo en segundos (ej. 60 segundos)
    }

    public function isRateLimited($ip) {
        // Incrementa el contador de solicitudes para la IP
        $requestCount = $this->redis->incr("request_count:$ip");
        
        // Establece la expiración del contador de solicitudes si es la primera solicitud
        if ($requestCount === 1) {
            $this->redis->expire("request_count:$ip", $this->timeWindow);
        }

        // Verifica si se ha superado el límite de solicitudes
        if ($requestCount > $this->requestLimit) {
            return true; // La IP está limitada
        }

        return false; // La IP no ha alcanzado el límite
    }

    public function blockRequest($ip) {
        // Lógica para bloquear la solicitud, por ejemplo, devolviendo un código de estado HTTP 429
        header('HTTP/1.1 429 Too Many Requests');
        echo "You have exceeded the allowed number of requests. Please try again later.";
        exit;
    }
}
