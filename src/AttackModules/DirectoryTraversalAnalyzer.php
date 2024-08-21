<?php

class DirectoryTraversalAnalyzer {

    public function analyze($request) {
        $uri = $request['REQUEST_URI'] ?? '';

        // Verifica si la URI contiene secuencias sospechosas de Directory Traversal
        if ($this->containsTraversalSequences($uri)) {
            return true; // Ataque Directory Traversal detectado
        }

        // Decodifica la URI y verifica de nuevo
        $decodedUri = urldecode($uri);
        if ($this->containsTraversalSequences($decodedUri)) {
            return true; // Ataque Directory Traversal detectado en URI decodificada
        }

        // Verifica la longitud de la URI para detectar posibles intentos de evasión
        if ($this->isUriTooLong($uri)) {
            return true; // URI sospechosamente larga
        }

        // Verifica si la URI apunta a archivos sensibles
        if ($this->isSensitiveFileAccess($uri)) {
            return true; // Intento de acceder a archivos sensibles
        }

        return false;
    }

    private function containsTraversalSequences($uri) {
        // Detecta secuencias de Directory Traversal como ../ o ..\
        $patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e\\']; // Incluye variaciones codificadas
        foreach ($patterns as $pattern) {
            if (strpos($uri, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isUriTooLong($uri) {
        $maxLength = 2000; // Longitud máxima de la URI (ajustable)
        return strlen($uri) > $maxLength;
    }

    private function isSensitiveFileAccess($uri) {
        // Verifica si la URI intenta acceder a archivos sensibles del sistema
        $sensitiveFiles = [
            '/etc/passwd', 
            '/.env', 
            '/.htaccess',
            '/config.php', 
            '/wp-config.php'
        ];

        foreach ($sensitiveFiles as $file) {
            if (strpos($uri, $file) !== false) {
                return true;
            }
        }

        return false;
    }
}
