<?php

class HTTPParameterPollutionAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar el seguimiento del tráfico y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        // Analiza la cadena de consulta y los parámetros del cuerpo para detectar posibles ataques de HPP
        $queryParams = $_GET;
        $postParams = $_POST;

        // Verifica si hay parámetros duplicados en la cadena de consulta
        if ($this->hasDuplicateParameters($queryParams)) {
            $this->logAttack($request['REMOTE_ADDR'], 'HPP - Duplicate Query Parameters');
            return true;
        }

        // Verifica si hay parámetros duplicados en el cuerpo de la solicitud (para solicitudes POST)
        if ($this->hasDuplicateParameters($postParams)) {
            $this->logAttack($request['REMOTE_ADDR'], 'HPP - Duplicate POST Parameters');
            return true;
        }

        return false; // No se detectaron ataques de HPP
    }

    private function hasDuplicateParameters($params) {
        // Cuenta las ocurrencias de cada parámetro
        $paramCounts = array_count_values(array_keys($params));

        // Si algún parámetro aparece más de una vez, es un indicio de HPP
        foreach ($paramCounts as $param => $count) {
            if ($count > 1) {
                return true;
            }
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

