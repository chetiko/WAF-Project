<?php

require_once 'TrafficAnalyzer.php';
require_once 'BotDetector.php';
require_once 'CaptchaVerifier.php';
require_once 'ModelLoader.php';

class DDosMitigator {

    private $trafficAnalyzer;
    private $botDetector;
    private $captchaVerifier;
    private $modelLoader;
    private $redis;

    public function __construct() {
        // Inicializar Redis para manejo de tráfico
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);

        // Inicializar componentes
        $this->trafficAnalyzer = new TrafficAnalyzer($this->redis);
        $this->botDetector = new BotDetector();
        $this->captchaVerifier = new CaptchaVerifier('recaptcha', 'your_recaptcha_secret_key');
        
        // Inicializar el cargador de modelos de Machine Learning
        $this->modelLoader = new ModelLoader(__DIR__ . '/../data/model.json'); // Ruta del modelo JSON
    }

    public function mitigate($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';

        // 1. Analiza el tráfico para detectar patrones sospechosos
        if (!$this->trafficAnalyzer->analyze($request)) {
            $this->blockRequest($ip, 'Suspicious Traffic Detected');
        }

        // 2. Detecta posibles bots
        if ($this->botDetector->analyze($request)) {
            $this->blockRequest($ip, 'Bot Detected');
        }

        // 3. Predicción basada en Machine Learning
        $prediction = $this->modelLoader->predict($request);
        if ($prediction === 'malicious') {
            $this->blockRequest($ip, 'Predicted Malicious by ML Model');
        }

        // 4. Verifica si es necesario presentar un CAPTCHA
        if ($this->shouldPresentCaptcha($request)) {
            if (!$this->captchaVerifier->verifyCaptcha($request['g-recaptcha-response'], $ip)) {
                $this->captchaVerifier->handleCaptchaFailure();
                $this->blockRequest($ip, 'CAPTCHA Failed');
            }
        }

        // Si pasa todas las comprobaciones, permite la solicitud
        return true;
    }

    private function shouldPresentCaptcha($request) {
        $ip = $request['REMOTE_ADDR'] ?? '';
        // Presenta CAPTCHA si el comportamiento es sospechoso (por ejemplo, demasiadas solicitudes)
        $requestCount = $this->redis->get("request_count:$ip");
        return $requestCount > 50; // Umbral para mostrar CAPTCHA
    }

    private function blockRequest($ip, $reason) {
        // Bloquea la solicitud y devuelve un código de error
        header('HTTP/1.1 403 Forbidden');
        echo "Your request has been blocked: $reason";
        exit;
    }
}
