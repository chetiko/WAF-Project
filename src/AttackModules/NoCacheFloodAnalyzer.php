<?php

class NoCacheFloodAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar la frecuencia de solicitudes y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $uri = $request['REQUEST_URI'] ?? '';
        $ip = $request['REMOTE_ADDR'] ?? '';
        $headers = apache_request_headers();

        // Verifica si la URI contiene parámetros aleatorios sospechosos
        if ($this->containsRandomParameters($uri)) {
            // Monitorea la frecuencia de solicitudes con parámetros únicos desde la misma IP
            if ($this->isFloodingWithUniqueParameters($ip)) {
                return true; // Posible ataque NoCache Flood detectado
            }
        }

        // Verifica si las cabeceras solicitan evitar la caché
        if ($this->containsNoCacheHeaders($headers)) {
            return true; // Cabeceras sospechosas que solicitan evitar la caché
        }

        return false; // No se detectaron ataques NoCache Flood
    }

    private function containsRandomParameters($uri) {
        // Extrae los parámetros de la URI
        $queryString = parse_url($uri, PHP_URL_QUERY);
        if (!$queryString) {
            return false; // No hay parámetros en la URI
        }

        // Analiza los patrones de los parámetros en busca de aleatoriedad
        $pattern = '/nocache\d+/'; // Ejemplo de patrón para detectar parámetros aleatorios
        return preg_match($pattern, $queryString) === 1;
    }

    private function isFloodingWithUniqueParameters($ip) {
        // Obtiene el contador de parámetros únicos para esta IP en Redis
        $uniqueParamCount = $this->redis->incr("unique_param_count:$ip");
        $this->redis->expire("unique_param_count:$ip", 60); // Expira en 1 minuto

        // Define un umbral para la cantidad de parámetros únicos permitidos por minuto
        $threshold = 20; // Ajustable según las necesidades del servidor
        return $uniqueParamCount > $threshold;
    }

    private function containsNoCacheHeaders($headers) {
        // Verifica si las cabeceras contienen instrucciones para evitar la caché
        if (isset($headers['Cache-Control'])) {
            $cacheControl = $headers['Cache-Control'];
            if (strpos($cacheControl, 'no-store') !== false || strpos($cacheControl, 'no-cache') !== false) {
                return true;
            }
        }

        return false;
    }
}
