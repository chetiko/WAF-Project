<?php

class XXEAnalyzer {

    public function analyze($request) {
        // Verifica el tipo de contenido para asegurarse de que sea XML
        if (strpos($request['CONTENT_TYPE'], 'xml') !== false) {
            // Obtiene el cuerpo de la solicitud XML
            $xmlContent = file_get_contents("php://input");

            // Verifica si contiene una declaración de entidad externa
            if ($this->containsExternalEntity($xmlContent)) {
                return true; // Posible ataque XXE detectado
            }

            // Verifica si el XML contiene estructuras mal formadas o sospechosas
            if ($this->isMalformedXML($xmlContent)) {
                return true; // XML mal formado o sospechoso
            }

            // Verifica la complejidad del XML
            if ($this->isComplexXML($xmlContent)) {
                return true; // XML sospechosamente complejo
            }
        }

        return false;
    }

    private function containsExternalEntity($xmlContent) {
        // Verifica la presencia de entidades externas en el XML
        if (preg_match('/<!ENTITY.*(SYSTEM|PUBLIC).*?>/', $xmlContent)) {
            return true; // Contiene una entidad externa, lo que puede ser un ataque XXE
        }
        return false;
    }

    private function isMalformedXML($xmlContent) {
        // Intenta cargar el XML y verificar si está bien formado
        libxml_use_internal_errors(true);
        $xml = simplexml_load_string($xmlContent);
        if ($xml === false) {
            return true; // XML mal formado
        }
        return false;
    }

    private function isComplexXML($xmlContent) {
        // Calcula la complejidad del XML (número de elementos y profundidad)
        $xml = new SimpleXMLElement($xmlContent);
        $elementCount = count($xml->xpath('//*'));
        $maxAllowedElements = 1000; // Umbral ajustable para limitar la complejidad del XML

        if ($elementCount > $maxAllowedElements) {
            return true; // XML sospechosamente complejo
        }
        return false;
    }
}
