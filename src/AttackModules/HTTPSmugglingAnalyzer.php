<?php

class HTTPSmugglingAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar el seguimiento del tráfico y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $headers = apache_request_headers();

        // Verifica inconsistencias en los encabezados Content-Length y Transfer-Encoding
        if ($this->isContentLengthAndTransferEncodingInconsistent($headers)) {
            $this->logAttack($request['REMOTE_ADDR'], 'HTTP Smuggling - Inconsistent Headers');
            return true;
        }

        // Verifica si hay encabezados duplicados
        if ($this->hasDuplicateHeaders($headers)) {
            $this->logAttack($request['REMOTE_ADDR'], 'HTTP Smuggling - Duplicate Headers');
            return true;
        }

        // Verifica si la solicitud está fragmentada anómalamente
        if ($this->isChunkedEncodingAnomalous($headers)) {
            $this->logAttack($request['REMOTE_ADDR'], 'HTTP Smuggling - Anomalous Chunked Encoding');
            return true;
        }

        // Verifica si el cuerpo de la solicitud es anómalo
        if ($this->isRequestBodySuspicious($request)) {
            $this->logAttack($request['REMOTE_ADDR'], 'HTTP Smuggling - Suspicious Request Body');
            return true;
        }

        return false;
    }

    private function isContentLengthAndTransferEncodingInconsistent($headers) {
        // Verifica si ambos encabezados Content-Length y Transfer-Encoding están presentes y son inconsistentes
        if (isset($headers['Content-Length']) && isset($headers['Transfer-Encoding'])) {
            return true; // Inconsistencia entre Content-Length y Transfer-Encoding
        }
        return false;
    }

    private function hasDuplicateHeaders($headers) {
        // Verifica si hay encabezados HTTP duplicados
        $headerCounts = array_count_values(array_keys($headers));
        foreach ($headerCounts as $header => $count) {
            if ($count > 1) {
                return true; // Encabezado duplicado detectado
            }
        }
        return false;
    }

    private function isChunkedEncodingAnomalous($headers) {
        // Verifica si la solicitud utiliza chunked encoding de manera anómala
        if (isset($headers['Transfer-Encoding']) && strtolower($headers['Transfer-Encoding']) === 'chunked') {
            // Aquí puedes agregar más lógica para analizar el contenido chunked
            return false; // Placeholder, puede ampliarse
        }
        return false;
    }

    private function isRequestBodySuspicious($request) {
        // Analiza el cuerpo de la solicitud en busca de patrones inusuales
        $body = file_get_contents("php://input");
        // Verifica si el cuerpo contiene datos no esperados o mal formados
        if (strlen($body) > 0 && !isset($request['Content-Length'])) {
            return true; // Cuerpo inesperado sin Content-Length
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

