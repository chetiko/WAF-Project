<?php

class LFIAnalyzer {

    public function analyze($request) {
        $uri = $request['REQUEST_URI'] ?? '';
        $parameters = $this->getQueryParameters($uri);

        // Verifica si los parámetros contienen secuencias sospechosas de Directory Traversal
        foreach ($parameters as $param) {
            if ($this->containsTraversalSequences($param)) {
                return true; // Posible ataque LFI detectado
            }

            // Decodifica el parámetro y verifica de nuevo
            $decodedParam = urldecode($param);
            if ($this->containsTraversalSequences($decodedParam)) {
                return true; // Ataque LFI detectado en parámetro decodificado
            }

            // Verifica si se intenta acceder a archivos con extensiones peligrosas
            if ($this->isDangerousFileExtension($param)) {
                return true; // Intento de incluir un archivo peligroso
            }

            // Verifica si se intenta acceder a rutas absolutas
            if ($this->isAbsolutePath($param)) {
                return true; // Intento de acceder a un archivo fuera del directorio permitido
            }
        }

        return false; // No se detectaron ataques LFI
    }

    private function getQueryParameters($uri) {
        // Extrae los parámetros de la URI
        $queryString = parse_url($uri, PHP_URL_QUERY);
        parse_str($queryString, $params);
        return array_values($params);
    }

    private function containsTraversalSequences($param) {
        // Detecta secuencias de Directory Traversal como ../ o ..\
        $patterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e\\'];
        foreach ($patterns as $pattern) {
            if (strpos($param, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }

    private function isDangerousFileExtension($param) {
        // Verifica si el parámetro intenta acceder a archivos con extensiones peligrosas
        $dangerousExtensions = ['.php', '.env', '.log', '.conf', '.ini', '.sh'];
        foreach ($dangerousExtensions as $extension) {
            if (substr($param, -strlen($extension)) === $extension) {
                return true;
            }
        }
        return false;
    }

    private function isAbsolutePath($param) {
        // Verifica si el parámetro contiene una ruta absoluta comúnmente atacada
        $sensitivePaths = ['/etc/', '/var/', '/usr/', '/proc/'];
        foreach ($sensitivePaths as $path) {
            if (strpos($param, $path) === 0) { // La ruta comienza con un directorio sensible
                return true;
            }
        }
        return false;
    }
}

