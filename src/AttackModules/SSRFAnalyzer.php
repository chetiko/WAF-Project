<?php

class SSRFAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar el seguimiento del tráfico y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $url = $request['url'] ?? '';
        $headers = apache_request_headers();

        // Verifica si la URL apunta a una dirección IP privada o reservada
        if ($this->isPrivateIPAddress($url)) {
            $this->logAttack($request['REMOTE_ADDR'], 'SSRF - Private IP Access');
            return true;
        }

        // Verifica si la URL usa un protocolo no HTTP sospechoso
        if ($this->isSuspiciousProtocol($url)) {
            $this->logAttack($request['REMOTE_ADDR'], 'SSRF - Suspicious Protocol');
            return true;
        }

        // Verifica si la URL intenta acceder a servicios de backend específicos
        if ($this->isBackendServiceTargeted($url)) {
            $this->logAttack($request['REMOTE_ADDR'], 'SSRF - Backend Service Access');
            return true;
        }

        // Verifica si la URL o los encabezados de respuesta indican una redirección maliciosa
        if ($this->isMaliciousRedirection($headers)) {
            $this->logAttack($request['REMOTE_ADDR'], 'SSRF - Malicious Redirection');
            return true;
        }

        return false;
    }

    private function isPrivateIPAddress($url) {
        // Extrae la IP de la URL y verifica si pertenece a un rango de IP privado
        $host = parse_url($url, PHP_URL_HOST);
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            return $this->isPrivateIP($host);
        }
        return false;
    }

    private function isPrivateIP($ip) {
        // Verifica si la IP está en los rangos privados comunes
        $privateRanges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8', // Loopback
            '169.254.0.0/16', // Link-local
            '::1', // IPv6 loopback
            'fc00::/7', // IPv6 Unique Local Address (ULA)
        ];

        foreach ($privateRanges as $range) {
            if ($this->ipInRange($ip, $range)) {
                return true;
            }
        }

        return false;
    }

    private function ipInRange($ip, $range) {
        list($subnet, $mask) = explode('/', $range);
        return (ip2long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet);
    }

    private function isSuspiciousProtocol($url) {
        // Verifica si la URL usa un protocolo no HTTP (por ejemplo, file://, ftp://, etc.)
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $suspiciousSchemes = ['file', 'ftp', 'gopher', 'mailto', 'ldap', 'data', 'dict', 'sftp', 'ssh', 'telnet'];
        return in_array(strtolower($scheme), $suspiciousSchemes);
    }

    private function isBackendServiceTargeted($url) {
        // Verifica si la URL intenta acceder a servicios de backend como metadatos de la nube
        $backendServices = [
            '169.254.169.254', // AWS Metadata Service
            'metadata.google.internal', // Google Cloud Metadata Service
        ];

        foreach ($backendServices as $service) {
            if (strpos($url, $service) !== false) {
                return true;
            }
        }

        return false;
    }

    private function isMaliciousRedirection($headers) {
        // Verifica si la respuesta incluye redirecciones sospechosas
        if (isset($headers['Location'])) {
            $location = $headers['Location'];
            // Agrega lógica adicional para detectar redirecciones maliciosas
            return $this->isPrivateIPAddress($location);
        }
        return false;
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

