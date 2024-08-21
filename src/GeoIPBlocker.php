<?php

class GeoIPBlocker {

    private $geoProvider;
    private $blockedCountries;
    private $whitelistedIPs;

    public function __construct($geoProvider) {
        $this->geoProvider = $geoProvider; // Proveedor de geolocalización (ej. IPinfo, MaxMind)
        $this->blockedCountries = require(__DIR__ . '/../data/blocked_countries.php'); // Lista de países bloqueados
        $this->whitelistedIPs = require(__DIR__ . '/../data/whitelisted_ips.php'); // Lista de IPs permitidas
    }

    public function analyze($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';

        // Verifica si la IP está en la lista blanca
        if ($this->isWhitelisted($ip)) {
            return true; // Permitir la solicitud
        }

        // Obtén la geolocalización de la IP
        $geoInfo = $this->getGeoLocation($ip);

        // Verifica si el país está bloqueado
        if (in_array($geoInfo['country'], $this->blockedCountries)) {
            $this->blockRequest($ip, $geoInfo['country']);
        }

        return true; // Permitir la solicitud si no está bloqueada
    }

    private function getGeoLocation($ip) {
        // Utiliza el proveedor de geolocalización configurado para obtener la ubicación de la IP
        return $this->geoProvider->getGeoInfo($ip);
    }

    private function isWhitelisted($ip) {
        // Verifica si la IP está en la lista blanca
        return in_array($ip, $this->whitelistedIPs);
    }

    private function blockRequest($ip, $country) {
        // Bloquea la solicitud y devuelve un código de error
        header('HTTP/1.1 403 Forbidden');
        echo "Your request has been blocked due to your location ($country).";
        exit;
    }
}
