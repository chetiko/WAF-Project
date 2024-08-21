<?php

class BotDetector {

    private $redis;
    private $userAgentBlacklist;
    private $ipBlacklist;

    public function __construct() {
        // Conectar a Redis para manejar el seguimiento del tráfico y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);

        // Cargar la lista de User Agents y IPs bloqueadas desde archivos externos
        $this->userAgentBlacklist = require(__DIR__ . '/../data/user_agents_blacklist.php');
        $this->ipBlacklist = require(__DIR__ . '/../data/ip_blacklist.php');
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';
        $userAgent = $request['HTTP_USER_AGENT'] ?? '';

        // Verifica si el User-Agent está en la lista negra
        if ($this->isUserAgentBlocked($userAgent)) {
            $this->logBotDetection($ip, 'Blocked User-Agent');
            return true;
        }

        // Verifica si la IP está en la lista negra
        if ($this->isIPBlocked($ip)) {
            $this->logBotDetection($ip, 'Blocked IP');
            return true;
        }

        // Analiza el comportamiento del usuario
        if ($this->isSuspiciousBehavior($ip)) {
            $this->logBotDetection($ip, 'Suspicious Behavior');
            return true;
        }

        // Verifica si el bot falló en un desafío JavaScript
        if (!$this->passedJavaScriptChallenge()) {
            $this->logBotDetection($ip, 'Failed JavaScript Challenge');
            return true;
        }

        return false; // No se detectó actividad de bot
    }

    private function isUserAgentBlocked($userAgent) {
        // Verifica si el User-Agent está en la lista negra
        return in_array($userAgent, $this->userAgentBlacklist);
    }

    private function isIPBlocked($ip) {
        // Verifica si la IP está en la lista negra
        return in_array($ip, $this->ipBlacklist);
    }

    private function isSuspiciousBehavior($ip) {
        // Monitorea el comportamiento del usuario para detectar patrones sospechosos
        // Ejemplo: Número de solicitudes en un corto período de tiempo
        $requestCount = $this->redis->incr("request_count:$ip");
        $this->redis->expire("request_count:$ip", 60); // Expira en 1 minuto

        // Si se realizan más de 100 solicitudes en un minuto, es sospechoso
        return $requestCount > 100;
    }

    private function passedJavaScriptChallenge() {
        // Verifica si el visitante pasó un desafío basado en JavaScript
        // Puedes implementar desafíos simples, como calcular un valor en JavaScript y devolverlo al servidor
        // Placeholder para lógica de desafío JavaScript
        return true; // Simula que el desafío fue pasado
    }

    private function logBotDetection($ip, $detectionType) {
        // Registra la detección del bot en un archivo de log
        $logMessage = sprintf(
            "[%s] %s detected from IP %s\n",
            date('Y-m-d H:i:s'),
            $detectionType,
            $ip
        );
        file_put_contents(__DIR__ . '/../logs/bot_detection.log', $logMessage, FILE_APPEND);
    }
}
