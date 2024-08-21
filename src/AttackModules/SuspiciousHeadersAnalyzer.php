<?php

class SuspiciousHeadersAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar la tasa de solicitudes y almacenar información temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $headers = apache_request_headers();
        $ip = $request['REMOTE_ADDR'];

        // Verificación de encabezados comunes
        if ($this->missingCommonHeaders($headers)) {
            return true; // Faltan encabezados esenciales
        }

        // Detección de encabezados manipulados
        if ($this->detectManipulatedHeaders($headers)) {
            return true; // Encabezados manipulados detectados
        }

        // Análisis del encabezado User-Agent
        if ($this->isSuspiciousUserAgent($headers['User-Agent'] ?? '')) {
            return true; // User-Agent sospechoso
        }

        // Validación del tamaño y estructura de los encabezados
        if ($this->isMalformedHeaders($headers)) {
            return true; // Encabezados mal formados
        }

        // Verificación del Referer
        if ($this->isSuspiciousReferer($headers['Referer'] ?? '')) {
            return true; // Referer sospechoso
        }

        return false;
    }

    private function missingCommonHeaders($headers) {
        // Verifica la presencia de encabezados comunes como Host, User-Agent, Referer, etc.
        $commonHeaders = ['Host', 'User-Agent', 'Referer', 'Content-Type'];
        foreach ($commonHeaders as $header) {
            if (empty($headers[$header])) {
                return true; // Faltan encabezados esenciales
            }
        }
        return false;
    }

    private function detectManipulatedHeaders($headers) {
        // Ejemplo de verificación de encabezado Host que no coincide con el dominio esperado
        $expectedHost = 'www.tu-dominio.com'; // Ajustar a tu dominio
        if (isset($headers['Host']) && $headers['Host'] !== $expectedHost) {
            return true; // Host manipulado
        }
        
        // Verificar otros encabezados sospechosos o manipulados
        if (isset($headers['X-Forwarded-For']) && !$this->isValidXForwardedFor($headers['X-Forwarded-For'])) {
            return true; // X-Forwarded-For sospechoso
        }

        return false;
    }

    private function isValidXForwardedFor($xForwardedFor) {
        // Valida que X-Forwarded-For contenga una IP válida
        return filter_var($xForwardedFor, FILTER_VALIDATE_IP) !== false;
    }

    private function isSuspiciousUserAgent($userAgent) {
        // Verifica el User-Agent contra una lista negra y analiza patrones sospechosos
        $blacklistedAgents = include(__DIR__ . '/../data/user_agents_blacklist.php');
        if (in_array($userAgent, $blacklistedAgents)) {
            return true; // User-Agent en lista negra
        }

        // Verificar si el User-Agent está vacío o es sospechoso
        if (empty($userAgent) || strlen($userAgent) < 10) {
            return true; // User-Agent vacío o demasiado corto
        }

        return false;
    }

    private function isMalformedHeaders($headers) {
        // Verifica si los encabezados son extremadamente largos o contienen caracteres no válidos
        foreach ($headers as $header => $value) {
            if (strlen($value) > 1000 || preg_match('/[^\x20-\x7E]/', $value)) {
                return true; // Encabezado sospechosamente largo o mal formado
            }
        }
        return false;
    }

    private function isSuspiciousReferer($referer) {
        // Verifica si el Referer está vacío o es inconsistente
        if (empty($referer)) {
            return true; // Referer vacío
        }

        // Verifica si el Referer coincide con los patrones esperados
        $expectedDomains = ['www.tu-dominio.com', 'tu-dominio.com']; // Ajustar según tu sitio
        foreach ($expectedDomains as $domain) {
            if (strpos($referer, $domain) !== false) {
                return false; // Referer válido
            }
        }

        return true; // Referer sospechoso
    }
}
