<?php

class LargePayloadPOSTAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar la frecuencia de solicitudes y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? 0;

        // Verifica si la solicitud es un POST con un tamaño de contenido significativo
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && $contentLength > 0) {
            // Verifica si el tamaño del payload es demasiado grande
            if ($this->isPayloadTooLarge($contentLength)) {
                return true; // Se detecta un ataque con payload grande
            }

            // Monitorea la frecuencia de solicitudes POST con grandes cargas útiles
            if ($this->isFrequentLargePayload($ip)) {
                return true; // Se detecta un ataque con múltiples grandes cargas útiles
            }

            // Verifica si el contenido del payload parece anómalo
            if ($this->isAnomalousPayloadContent($request)) {
                return true; // Payload anómalo detectado
            }

            // Verifica la coherencia del encabezado Content-Length
            if ($this->isContentLengthMismatch($contentLength, $request)) {
                return true; // Manipulación del encabezado Content-Length detectada
            }
        }

        return false; // No se detectaron ataques con grandes payloads
    }

    private function isPayloadTooLarge($contentLength) {
        // Define un umbral para el tamaño máximo de payload permitido
        $maxPayloadSize = 10 * 1024 * 1024; // 10 MB, ajustable
        return $contentLength > $maxPayloadSize;
    }

    private function isFrequentLargePayload($ip) {
        // Incrementa el contador de grandes cargas útiles para esta IP en Redis
        $largePayloadCount = $this->redis->incr("large_payload_count:$ip");
        $this->redis->expire("large_payload_count:$ip", 60); // Expira en 1 minuto

        // Define un umbral para la cantidad de grandes cargas útiles permitidas por minuto
        $threshold = 5; // Ajustable según las necesidades del servidor
        return $largePayloadCount > $threshold;
    }

    private function isAnomalousPayloadContent($request) {
        // Analiza el contenido del payload en busca de patrones anómalos
        $payload = file_get_contents("php://input");

        // Verifica si el payload contiene datos repetitivos o sospechosos
        if (preg_match('/(.)\1{100,}/', $payload)) {
            return true; // Se detecta un patrón repetitivo anómalo
        }

        // Agregar más lógica de análisis de contenido según sea necesario
        return false;
    }

    private function isContentLengthMismatch($contentLength, $request) {
        // Verifica si el encabezado Content-Length coincide con el tamaño real del payload
        $payload = file_get_contents("php://input");
        return strlen($payload) != $contentLength;
    }
}
