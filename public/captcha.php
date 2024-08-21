<?php
session_start();

// Clave secreta de reCAPTCHA (debe obtenerse de la cuenta de Google reCAPTCHA)
$secretKey = 'your-secret-key';

// Si el formulario fue enviado
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Verifica la respuesta del CAPTCHA
    $recaptchaResponse = $_POST['g-recaptcha-response'];
    $userIP = $_SERVER['REMOTE_ADDR'];

    $url = 'https://www.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $secretKey,
        'response' => $recaptchaResponse,
        'remoteip' => $userIP
    ];

    // Realiza la solicitud a Google reCAPTCHA
    $options = [
        'http' => [
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($data),
        ],
    ];

    $context  = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    $responseKeys = json_decode($result, true);

    // Si el CAPTCHA fue exitoso
    if ($responseKeys['success']) {
        $_SESSION['captcha_passed'] = true;
        header('Location: /'); // Redirige a la página principal después de pasar el CAPTCHA
        exit();
    } else {
        $errorMessage = "CAPTCHA fallido. Por favor, intente nuevamente.";
    }
}

?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Verificación CAPTCHA</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
</head>
<body>

<h1>Por favor, verifique que usted es humano</h1>

<?php if (!empty($errorMessage)): ?>
    <p style="color: red;"><?php echo $errorMessage; ?></p>
<?php endif; ?>

<form action="captcha.php" method="POST">
    <div class="g-recaptcha" data-sitekey="your-site-key"></div>
    <br/>
    <input type="submit" value="Verificar">
</form>

</body>
</html>
