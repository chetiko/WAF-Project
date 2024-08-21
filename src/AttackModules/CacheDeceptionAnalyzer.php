<?php

class CacheDeceptionAnalyzer {

    public function analyze($request) {
        $uri = $request['REQUEST_URI'] ?? '';
        $method = $request['REQUEST_METHOD'] ?? 'GET';
        $headers = apache_request_headers();

        // Verifica si la solicitud GET intenta acceder a contenido sensible
        if ($method === 'GET' && $this->isSensitivePath($uri)) {
            return true; // Posible ataque de Cache Deception detectado
        }

        // Verifica la cabecera Cache-Control y otras cabeceras relacionadas con la caché
        if ($this->isSuspiciousCacheHeader($headers)) {
            return true; // Cabeceras de caché sospechosas detectadas
        }

        // Verifica si la URI contiene parámetros inusuales
        if ($this->containsSuspiciousParameters($uri)) {
            return true; // Parámetros sospechosos detectados en la URI
        }

        return false; // No se detectaron ataques de Cache Deception
    }

    private function isSensitivePath($uri) {
        // Verifica rutas que no deberían estar accesibles mediante GET ni almacenarse en la caché
        $sensitivePaths = ['/login', '/checkout', '/profile', '/settings'];
        foreach ($sensitivePaths as $path) {
            if (strpos($uri, $path) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isSuspiciousCacheHeader($headers) {
        // Verifica si las cabeceras de caché están mal configuradas
        if (isset($headers['Cache-Control']) && strpos($headers['Cache-Control'], 'private') === false) {
            return true; // La cabecera Cache-Control no está configurada como privada
        }
        return false;
    }

    private function containsSuspiciousParameters($uri) {
        // Verifica si la URI contiene parámetros de consulta sospechosos
        $suspiciousPatterns = ['dummyparam', 'cachebuster', 'sessionid'];
        foreach ($suspiciousPatterns as $pattern) {
            if (strpos($uri, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }
}

