<?php
namespace OAuth2\EventListener;

use OAuth2\Event\GenerateTokenEvent;

/**
 * Random token generator
 * 
 * @author Charles J. C Elling <tlakomistli.anakmosatlani@gmail.com>
 *
 */
class GenerateRandomTokenListener
{
    /**
     * Generate random token
     * 
     * @param GenerateTokenEvent $event
     */
    public function generateRandomToken(GenerateTokenEvent $event) 
    {
        if (@file_exists('/dev/urandom')) { // Get 100 bytes of random data
            $randomData = file_get_contents('/dev/urandom', false, null, 0, 100);
        } elseif (function_exists('openssl_random_pseudo_bytes')) { // Get 100 bytes of pseudo-random data
            $bytes = openssl_random_pseudo_bytes(100, $strong);
            if (true === $strong && false !== $bytes) {
                $randomData = $bytes;
            }
        }
        // Last resort: mt_rand
        if (empty($randomData)) { // Get 108 bytes of (pseudo-random, insecure) data
            $randomData = mt_rand() . mt_rand() . mt_rand() . uniqid(mt_rand(), true) . microtime(true) . uniqid(
                mt_rand(),
                true
                );
        }
        
        $token = rtrim(strtr(base64_encode(hash('sha256', $randomData)), '+/', '-_'), '=');
        $event->setToken($token);
    }
}