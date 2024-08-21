<?php

class HTTPRangeAnalyzer {

    private $redis;

    public function __construct() {
        // Conexión a Redis para gestionar el estado temporal de las solicitudes de rango
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'];
        $rangeHeader = $request['HTTP_RANGE'] ?? '';

        // Verifica si hay un encabezado HTTP Range presente
        if ($rangeHeader) {
            // Verifica si la solicitud de rango es sospechosa
            if ($this->isSuspiciousRangeRequest($ip, $rangeHeader)) {
                return true;  // Se detecta un posible ataque HTTP Range
            }
        }

        return false;
    }

    private function isSuspiciousRangeRequest($ip, $rangeHeader) {
        // Verifica si la solicitud de rango contiene múltiples rangos (indicativo de un ataque)
        if (strpos($rangeHeader, ',') !== false) {
            // Almacena la cantidad de rangos solicitados por esta IP en Redis
            $rangeCount = $this->redis->incr("range_count:$ip");
            $this->redis->expire("range_count:$ip", 3600); // Expira en 1 hora

            // Si se superan múltiples solicitudes de rangos, se considera sospechoso
            if ($rangeCount > $this->getRangeThreshold()) {
                return true;
            }
        }

        // Análisis más profundo: detectar patrones anormales en los rangos solicitados
        if ($this->detectAnomalousRangePattern($rangeHeader)) {
            return true;
        }

        return false;
    }

    private function getRangeThreshold() {
        return 10;  // Umbral de solicitudes de rangos en una hora (ajustable)
    }

    private function detectAnomalousRangePattern($rangeHeader) {
        // Descompone el encabezado HTTP Range para analizar los rangos solicitados
        $ranges = explode(',', $rangeHeader);

        foreach ($ranges as $range) {
            // Extrae los valores de inicio y fin del rango
            $parts = explode('-', $range);
            $start = isset($parts[0]) ? intval($parts[0]) : -1;
            $end = isset($parts[1]) ? intval($parts[1]) : -1;

            // Detecta si el rango es sospechosamente pequeño o anormal
            if ($this->isSuspiciousRange($start, $end)) {
                return true;
            }
        }

        return false;
    }

    private function isSuspiciousRange($start, $end) {
        // Umbral configurable para detectar rangos sospechosamente pequeños o amplios
        $minRangeSize = 1000;  // Ejemplo: el rango mínimo permitido
        $maxRangeSize = 1000000;  // Ejemplo: el rango máximo permitido

        // Detecta si el rango es anormal (muy pequeño o muy grande)
        if (($end - $start) < $minRangeSize || ($end - $start) > $maxRangeSize) {
            return true;
        }

        return false;
    }
}

