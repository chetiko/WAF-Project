<?php

require_once __DIR__ . '/../vendor/autoload.php';
use ipinfo\ipinfo\IPinfo;

class HTTPReflectionAnalyzer {

    private $redis;
    private $ipinfo;
    private $userAgentBlacklist;

    public function __construct() {
        // Conectar a Redis para manejar el seguimiento del tráfico y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);

        // Inicializar el cliente de IPinfo con tu token de acceso
        $access_token = 'your_ipinfo_token';  // Reemplaza con tu token
        $this->ipinfo = new IPinfo($access_token);

        // Cargar la lista de User Agents bloqueados desde un archivo externo
        $this->userAgentBlacklist = require(__DIR__ . '/../data/user_agents_blacklist.php');
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';
        $headers = apache_request_headers();

        // Verifica si el User-Agent está en la lista negra
        if ($this->isUserAgentBlocked($headers['User-Agent'] ?? '')) {
            $this->logAttack($ip, 'Blocked User-Agent');
            return true;
        }

        // Verifica si las cabeceras HTTP son sospechosas o están manipuladas
        if ($this->isSuspiciousHeaders($headers)) {
            $this->logAttack($ip, 'Suspicious Headers');
            return true;
        }

        // Verifica si la IP de origen es sospechosa o ha generado un gran volumen de tráfico (spoofing detection)
        if ($this->isIPSourceSpoofed($ip)) {
            $this->logAttack($ip, 'IP Spoofing');
            return true;
        }

        // Monitorea la tasa de respuestas generadas por el servidor
        if ($this->isFloodingResponses($ip)) {
            $this->logAttack($ip, 'Flooding Responses');
            return true;
        }

        // Verifica si el tamaño de la respuesta es inusualmente grande
        if ($this->isResponseSizeTooLarge($request)) {
            $this->logAttack($ip, 'Large Response Size');
            return true;
        }

        return false; // No se detectaron ataques de reflexión HTTP
    }

    private function isUserAgentBlocked($userAgent) {
        // Verifica si el User-Agent está en la lista negra
        return in_array($userAgent, $this->userAgentBlacklist);
    }

    private function isSuspiciousHeaders($headers) {
        // Verifica cabeceras HTTP comunes que suelen estar ausentes o mal formadas en ataques de reflexión
        if (!isset($headers['User-Agent']) || !isset($headers['Host'])) {
            return true; // Faltan cabeceras esenciales, posible ataque de reflexión
        }

        return false;
    }

    private function isIPSourceSpoofed($ip) {
        // Monitorea el tráfico de una IP específica
        $requestCount = $this->redis->incr("request_count:$ip");
        $this->redis->expire("request_count:$ip", 60); // Expira en 1 minuto

        // Define un umbral para la cantidad de solicitudes permitidas por IP en un minuto
        $threshold = 100;

        // Verificación de Geolocalización usando IPinfo
        $geoInfo = $this->getGeoLocation($ip);
        if ($this->isGeoLocationSuspicious($geoInfo)) {
            return true;
        }

        // Monitoreo de paquetes ICMP "Destination Unreachable" o TCP RST
        if ($this->isReceivingUnreachableOrRST($ip)) {
            return true;
        }

        return $requestCount > $threshold;
    }

    private function getGeoLocation($ip) {
        try {
            $details = $this->ipinfo->getDetails($ip);
            return [
                'country' => $details->country ?? 'Unknown',
                'city' => $details->city ?? 'Unknown'
            ];
        } catch (Exception $e) {
            return [
                'country' => 'Unknown',
                'city' => 'Unknown'
            ];
        }
    }

    private function isGeoLocationSuspicious($geoInfo) {
        $allowedCountries = ['US', 'CA'];
        return !in_array($geoInfo['country'], $allowedCountries);
    }

    private function isReceivingUnreachableOrRST($ip) {
        return false; // Placeholder para integración real
    }

    private function isFloodingResponses($ip) {
        $responseCount = $this->redis->incr("response_count:$ip");
        $this->redis->expire("response_count:$ip", 60);

        $threshold = 50;
        return $responseCount > $threshold;
    }

    private function isResponseSizeTooLarge($request) {
        $responseSize = strlen($this->generateResponse($request));

        $maxResponseSize = 100 * 1024;
        return $responseSize > $maxResponseSize;
    }

    private function generateResponse($request) {
        return "This is a simulated response for testing purposes.";
    }

    private function logAttack($ip, $attackType) {
        $logMessage = sprintf(
            "[%s] %s detected from IP %s\n",
            date('Y-m-d H:i:s'),
            $attackType,
            $ip
        );
        file_put_contents(__DIR__ . '/../logs/waf.log', $logMessage, FILE_APPEND);

        $detectionCount = $this->redis->incr("attack_detection_count:$ip");
        if ($detectionCount >= $this->alertThreshold) {
            $this->sendAlert($ip, $attackType);
            $this->redis->del("attack_detection_count:$ip");
        }
    }

    private function sendAlert($ip, $attackType) {
        $alertMessage = sprintf(
            "ALERT: Multiple %s attacks detected from IP %s",
            $attackType,
            $ip
        );
        echo $alertMessage;
    }
}
