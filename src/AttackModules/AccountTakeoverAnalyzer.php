<?php

class AccountTakeoverAnalyzer {

    private $redis;

    public function __construct() {
        // Conectar a Redis para manejar tasas y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';
        $userId = $request['user_id'] ?? '';
        $geoLocation = $this->getGeoLocation($ip);
        $userAgent = $request['HTTP_USER_AGENT'] ?? '';

        // Verifica intentos fallidos de inicio de sesión en un período corto
        if ($this->hasTooManyFailedLogins($userId)) {
            return true; // Posible intento de secuestro de cuenta detectado
        }

        // Verifica si el inicio de sesión proviene de una ubicación geográfica inusual
        if ($this->isUnusualGeoLocation($userId, $geoLocation)) {
            return true; // Inicio de sesión desde una ubicación sospechosa
        }

        // Verifica si el inicio de sesión se realiza desde un dispositivo desconocido
        if ($this->isUnknownDevice($userId, $userAgent)) {
            return true; // Dispositivo desconocido detectado
        }

        // Verifica cambios anómalos en el comportamiento del usuario
        if ($this->detectAnomalousBehavior($userId)) {
            return true; // Comportamiento anómalo en la cuenta
        }

        return false; // No se detectaron intentos de secuestro de cuenta
    }

    private function hasTooManyFailedLogins($userId) {
        // Implementa la lógica para verificar el número de intentos fallidos de inicio de sesión
        $failedLoginKey = "failed_login_count:$userId";
        $failedLogins = $this->redis->get($failedLoginKey) ?? 0;

        // Define un umbral para el número de intentos fallidos
        $threshold = 5;
        return $failedLogins > $threshold;
    }

    private function isUnusualGeoLocation($userId, $geoLocation) {
        // Verifica si el inicio de sesión proviene de una ubicación geográfica inusual
        $lastGeoLocationKey = "last_geo_location:$userId";
        $lastGeoLocation = $this->redis->get($lastGeoLocationKey);

        if ($lastGeoLocation && $lastGeoLocation !== $geoLocation) {
            return true; // La ubicación ha cambiado drásticamente
        }

        // Actualiza la ubicación geográfica del usuario
        $this->redis->set($lastGeoLocationKey, $geoLocation);
        return false;
    }

    private function isUnknownDevice($userId, $userAgent) {
        // Verifica si el inicio de sesión se realiza desde un dispositivo desconocido
        $knownDevicesKey = "known_devices:$userId";
        $knownDevices = $this->redis->smembers($knownDevicesKey);

        if (!in_array($userAgent, $knownDevices)) {
            // El dispositivo es desconocido, regístralo
            $this->redis->sadd($knownDevicesKey, $userAgent);
            return true;
        }

        return false;
    }

    private function detectAnomalousBehavior($userId) {
        // Monitorea cambios repentinos en el comportamiento del usuario
        // Implementa lógica para detectar cambios de contraseña, transferencias de fondos, etc.
        return false; // Placeholder para lógica avanzada
    }

    private function getGeoLocation($ip) {
        // Implementa la lógica para obtener la ubicación geográfica de la IP
        // Utiliza una API de terceros como IPinfo o GeoIP2
        return 'Unknown'; // Placeholder
    }
}

