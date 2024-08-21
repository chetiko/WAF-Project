<?php

class CSRFAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar el seguimiento del tráfico y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        // Verifica si el token CSRF es válido
        if (!$this->isValidCSRFToken($request)) {
            $this->logAttack($request['REMOTE_ADDR'], 'CSRF - Invalid Token');
            return true;
        }

        // Verifica si el encabezado Referer es válido
        if (!$this->isValidReferer($request)) {
            $this->logAttack($request['REMOTE_ADDR'], 'CSRF - Invalid Referer');
            return true;
        }

        // Monitorea si se trata de una acción sensible
        if ($this->isSensitiveAction($request)) {
            // Verifica si el token CSRF y el referer son válidos para acciones sensibles
            if (!$this->isValidCSRFToken($request) || !$this->isValidReferer($request)) {
                $this->logAttack($request['REMOTE_ADDR'], 'CSRF - Sensitive Action');
                return true;
            }
        }

        return false; // No se detectó ataque CSRF
    }

    private function isValidCSRFToken($request) {
        // Verifica si el token CSRF existe y es válido
        $token = $request['csrf_token'] ?? '';
        $sessionToken = $_SESSION['csrf_token'] ?? '';
        return !empty($token) && hash_equals($sessionToken, $token);
    }

    private function isValidReferer($request) {
        // Verifica si el encabezado Referer es de un origen confiable
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        $validReferer = 'https://your-domain.com'; // Cambia esto por tu dominio
        return strpos($referer, $validReferer) === 0;
    }

    private function isSensitiveAction($request) {
        // Define acciones sensibles, como cambios de contraseña o transferencias de dinero
        $sensitiveActions = [
            '/account/change-password',
            '/account/update-email',
            '/bank/transfer-money',
            // Agrega más acciones aquí
        ];

        return in_array($_SERVER['REQUEST_URI'], $sensitiveActions);
    }

    private function logAttack($ip, $attackType) {
        // Registra el ataque en un archivo de log
        $logMessage = sprintf(
            "[%s] %s detected from IP %s\n",
            date('Y-m-d H:i:s'),
            $attackType,
            $ip
        );
        file_put_contents(__DIR__ . '/../logs/waf.log', $logMessage, FILE_APPEND);
    }
}

