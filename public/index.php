<?php

// Habilitar el informe de errores para desarrollo (deshabilitar en producción)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Cargar el autoloader de Composer (si se usa Composer para dependencias)
require __DIR__ . '/../vendor/autoload.php';

// Incluir el archivo de configuración del WAF (si es necesario)
require_once __DIR__ . '/../src/WAF.php';

// Crear una instancia del WAF
$waf = new WAF();

// Obtener la solicitud actual
$request = $_SERVER;

// Manejar la solicitud a través del WAF
$waf->handleRequest($request);

// Si la solicitud pasa por todas las verificaciones, carga la aplicación principal
// Aquí podrías redirigir a una página de inicio o cargar el contenido principal de la aplicación
echo "Bienvenido a la aplicación protegida.";
