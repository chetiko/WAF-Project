<?php

class HTTPFloodAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar tasas y almacenar datos temporales
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'];
        $userAgent = $request['HTTP_USER_AGENT'] ?? '';

        // Monitorea la tasa de solicitudes
        if ($this->isFlooding($ip)) {
            return true;
        }

        // Verifica si hay ráfagas de solicitudes en intervalos cortos
        if ($this->detectBurstPatterns($ip)) {
            return true;
        }

        // Inspecciona el User-Agent y las cabeceras para detectar patrones sospechosos
        if ($this->isSuspiciousUserAgent($userAgent)) {
            return true;
        }

        // Monitorea patrones de uso de métodos HTTP
        if ($this->detectAbnormalHTTPMethods($request)) {
            return true;
        }

        // Detecta patrones distribuidos de múltiples IPs
        if ($this->detectDistributedFloodPatterns($request)) {
            return true;
        }

        return false;
    }

    private function isFlooding($ip) {
        $rate = $this->getRequestRate($ip);

        // Si la tasa de solicitudes supera el umbral, podría ser un ataque flood
        if ($rate > $this->getRateThreshold()) {
            return true;
        }

        return false;
    }

    private function getRequestRate($ip) {
        $rate = $this->redis->get($ip);
        if (!$rate) {
            $rate = 0;
        }

        $this->redis->incr($ip);
        $this->redis->expire($ip, 60); // Restablece el contador cada 60 segundos
        return $rate;
    }

    private function getRateThreshold() {
        return 100;  // Umbral de solicitudes por minuto
    }

    private function detectBurstPatterns($ip) {
        $timestamps = $this->redis->lrange("timestamps:$ip", 0, -1);

        if (count($timestamps) > 5) {
            $timeInterval = end($timestamps) - reset($timestamps);
            if ($timeInterval < 1) {  // Todas las solicitudes en menos de 1 segundo
                return true;
            }
        }

        $this->redis->rpush("timestamps:$ip", time());
        $this->redis->expire("timestamps:$ip", 60); // Restablece cada 60 segundos

        return false;
    }

    private function isSuspiciousUserAgent($userAgent) {
        $blacklistedAgents = include(__DIR__ . '/../data/user_agents_blacklist.php');
        return in_array($userAgent, $blacklistedAgents);
    }

    private function detectAbnormalHTTPMethods($request) {
        $method = $request['REQUEST_METHOD'] ?? '';
        $ip = $request['REMOTE_ADDR'];
        $methodKey = "methods:$ip:$method";

        $count = $this->redis->incr($methodKey);
        $this->redis->expire($methodKey, 60);

        if ($count > 50) {  // Más de 50 solicitudes del mismo método en un minuto
            return true;
        }

        return false;
    }

    private function detectDistributedFloodPatterns($request) {
        $ip = $request['REMOTE_ADDR'];
        $url = $request['REQUEST_URI'] ?? '';

        $patternKey = "distributed_flood:" . md5($url);
        $this->redis->sadd($patternKey, $ip);
        $this->redis->expire($patternKey, 60);

        $uniqueIps = $this->redis->scard($patternKey);

        // Si más de 10 IPs acceden a la misma URL en un corto período de tiempo, podría ser un ataque distribuido
        if ($uniqueIps > 10) {
            return true;
        }

        return false;
    }
}
