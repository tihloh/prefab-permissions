<?php

namespace Tihloh\Prefab\Permissions\Support;

final class CompactId
{
    private const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyz';

    public static function make(): string
    {
        $milliseconds = (int) floor(microtime(true) * 1000);
        $time = strtolower(base_convert((string) $milliseconds, 10, 36));
        $time = str_pad($time, 9, '0', STR_PAD_LEFT);

        $random = '';
        for ($i = 0; $i < 7; $i++) {
            $random .= self::ALPHABET[random_int(0, 35)];
        }

        return $time . $random;
    }
}
