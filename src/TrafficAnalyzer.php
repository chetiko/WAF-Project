<?php

class TrafficAnalyzer {

    private $modules;

    public function __construct() {
        // Inicializa los módulos de análisis desde la carpeta AttackModules
        $this->modules = [
            new AttackModules\HTTPFloodAnalyzer(),              // Detección de HTTP Flood
            new AttackModules\SlowlorisAnalyzer(),              // Detección de Slowloris
            new AttackModules\RUDYAnalyzer(),                   // Detección de RUDY (Slow POST)
            new AttackModules\HTTPRangeAnalyzer(),              // Detección de HTTP Range Attack
            new AttackModules\SuspiciousHeadersAnalyzer(),      // Detección de encabezados HTTP sospechosos
            new AttackModules\XXEAnalyzer(),                    // Detección de inyección de entidades externas XML (XXE)
            new AttackModules\DirectoryTraversalAnalyzer(),     // Detección de Directory Traversal (Path Traversal)
            new AttackModules\LFIAnalyzer(),                    // Detección de Local File Inclusion (LFI)
            new AttackModules\RFIAnalyzer(),                    // Detección de Remote File Inclusion (RFI)
            new AttackModules\CacheDeceptionAnalyzer(),         // Detección de Web Cache Deception
            new AttackModules\HostHeaderInjectionAnalyzer(),    // Detección de inyección en el encabezado Host
            new AttackModules\AccountTakeoverAnalyzer(),        // Detección de Account Takeover (ATO)
            new AttackModules\SlowPostAnalyzer(),               // Detección de ataques Slow POST
            new AttackModules\NoCacheFloodAnalyzer(),           // Detección de Randomized NoCache Flood
            new AttackModules\HTTPSlowReadAnalyzer(),           // Detección de ataques HTTP Slow Read
            new AttackModules\HTTPConnectionFloodAnalyzer(),    // Detección de HTTP Connection Flood
            new AttackModules\LargePayloadPOSTAnalyzer(),       // Detección de Large Payload POST
            new AttackModules\HTTPReflectionAnalyzer(),         // Detección de HTTP Reflection/Amplification Attack
            new AttackModules\HTTPSmugglingAnalyzer(),          // Detección de HTTP Smuggling
            new AttackModules\HTTPResponseSplittingAnalyzer(),  // Detección de HTTP Response Splitting
            new AttackModules\HTTPParameterPollutionAnalyzer(), // Detección de HTTP Parameter Pollution (HPP)
            new AttackModules\SSRFAnalyzer(),                   // Detección de Server-Side Request Forgery (SSRF)
            new AttackModules\CSRFAnalyzer(),                   // Detección de Cross-Site Request Forgery (CSRF)
        ];
    }

    public function detectAnomaly($request) {
        // Itera sobre todos los módulos de análisis
        foreach ($this->modules as $module) {
            if ($module->analyze($request)) {
                // Si se detecta una anomalía, se toma una acción
                $this->logAttack($request, get_class($module));
                return true; // Anomalía detectada, detener el análisis
            }
        }
        return false; // No se detectaron anomalías
    }

    private function logAttack($request, $moduleName) {
        // Registra el ataque en un log
        $logMessage = sprintf(
            "[%s] Anomaly detected by %s: IP %s, URI %s\n",
            date('Y-m-d H:i:s'),
            $moduleName,
            $request['REMOTE_ADDR'] ?? 'unknown',
            $request['REQUEST_URI'] ?? 'unknown'
        );

        // Escribe en el archivo de log
        file_put_contents(__DIR__ . '/../logs/waf.log', $logMessage, FILE_APPEND);
    }
}

