<?php

use Symfony\Component\ClassLoader\UniversalClassLoader;

$root = __DIR__ . '/../../../../';

require_once $root . 'vendor/Symfony/Component/ClassLoader/UniversalClassLoader.php';

$loader = new UniversalClassLoader;
$loader->registerNamespaces(array(
    'OAuth2' => $root.'lib',
    'Symfony' => $root.'vendor',
));

$loader->register();

require_once __DIR__ . '/OAuth2StoragePdo.php';

function newPDO()
{
    $settings = parse_ini_file(__DIR__ . '/settings.ini');
    $pdo = new PDO($settings['dsn'], $settings['user'], $settings['password']);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    return $pdo;
}
