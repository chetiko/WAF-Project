<?php

class WAF {
    private $trafficAnalyzer;
    private $geoIPBlocker;
    private $botDetector;
    private $rateLimiter;
    private $captchaVerifier;

    public function __construct() {
        // Inicializa los módulos
        $this->trafficAnalyzer = new TrafficAnalyzer();
        $this->geoIPBlocker = new GeoIPBlocker();
        $this->botDetector = new BotDetector();
        $this->rateLimiter = new RateLimiter();
        $this->captchaVerifier = new CaptchaVerifier();
    }

    public function handleRequest($request) {
        // Verifica si la IP está bloqueada por geolocalización
        if ($this->geoIPBlocker->isBlocked($request['REMOTE_ADDR'])) {
            $this->denyAccess("Acceso bloqueado por geolocalización.");
        }

        // Verifica si la tasa de solicitudes es sospechosa
        if ($this->rateLimiter->isRateLimitExceeded($request['REMOTE_ADDR'])) {
            $this->denyAccess("Demasiadas solicitudes en poco tiempo.");
        }

        // Verifica si es un bot, incluyendo AI scrapers y crawlers
        if ($this->botDetector->isBot($request)) {
            $this->denyAccess("Bot detectado.");
        }

        // Verifica si hay patrones de ataque DDoS o tráfico anómalo
        if ($this->trafficAnalyzer->detectAnomaly($request)) {
            $this->denyAccess("Ataque DDoS detectado.");
        }

        // Verifica si es necesario presentar un CAPTCHA
        if ($this->captchaVerifier->requiresCaptcha($request)) {
            $this->presentCaptcha();
        }

        // Si todo es seguro, permitir el acceso
        $this->allowAccess();
    }

    private function denyAccess($reason) {
        // Registrar el motivo del bloqueo
        file_put_contents(__DIR__ . '/../logs/waf.log', date('Y-m-d H:i:s') . " - Bloqueado: $reason\n", FILE_APPEND);
        // Respuesta HTTP de bloqueo
        header('HTTP/1.1 403 Forbidden');
        exit("Acceso denegado: $reason");
    }

    private function allowAccess() {
        // Permitir acceso a la aplicación
        // Aquí podrías redirigir al contenido principal de la aplicación.
        echo "Acceso permitido";
    }

    private function presentCaptcha() {
        // Redirigir a la página de CAPTCHA
        header('Location: /public/captcha.php');
        exit();
    }
}


