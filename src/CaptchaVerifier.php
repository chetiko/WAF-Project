<?php

class CaptchaVerifier {

    private $captchaProvider;
    private $secretKey;
    private $redis;

    public function __construct($captchaProvider, $secretKey) {
        $this->captchaProvider = $captchaProvider; // Ej. 'recaptcha', 'hcaptcha'
        $this->secretKey = $secretKey; // La clave secreta proporcionada por el servicio de CAPTCHA

        // Conectar a Redis para manejar el seguimiento del tráfico y almacenamiento temporal
        $this->redis = new Redis();
        $this->redis->connect('127.0.0.1', 6379);
    }

    public function verifyCaptcha($userResponse, $remoteIp) {
        switch ($this->captchaProvider) {
            case 'recaptcha':
                return $this->verifyRecaptcha($userResponse, $remoteIp);
            case 'hcaptcha':
                return $this->verifyHcaptcha($userResponse, $remoteIp);
            default:
                throw new Exception('CAPTCHA provider not supported.');
        }
    }

    private function verifyRecaptcha($userResponse, $remoteIp) {
        $url = 'https://www.google.com/recaptcha/api/siteverify';
        $data = [
            'secret' => $this->secretKey,
            'response' => $userResponse,
            'remoteip' => $remoteIp
        ];

        $response = $this->sendRequest($url, $data);
        return isset($response['success']) && $response['success'] === true;
    }

    private function verifyHcaptcha($userResponse, $remoteIp) {
        $url = 'https://hcaptcha.com/siteverify';
        $data = [
            'secret' => $this->secretKey,
            'response' => $userResponse,
            'remoteip' => $remoteIp
        ];

        $response = $this->sendRequest($url, $data);
        return isset($response['success']) && $response['success'] === true;
    }

    private function sendRequest($url, $data) {
        $options = [
            'http' => [
                'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
                'method'  => 'POST',
                'content' => http_build_query($data),
            ],
        ];

        $context  = stream_context_create($options);
        $result = file_get_contents($url, false, $context);
        return json_decode($result, true);
    }

    public function handleCaptchaFailure() {
        // Aquí podrías registrar el fallo o redirigir al usuario a un nuevo intento
        // Además, podrías implementar lógica de bloqueo temporal para IPs que fallan repetidamente
        echo "Captcha verification failed. Please try again.";
    }
}

