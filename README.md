# Crypto Sodium

A simple library that packages [functional `sodium_crypt_*`](https://www.php.net/manual/en/book.sodium.php) into objects.

Inputs and outputs are binary data, don't be afraid to use the [`petrknap/binary`](https://github.com/petrknap/php-binary).


## Examples

### Symmetric block encryption

```php
use PetrKnap\CryptoSodium\SecretBox;

$secretBox = new SecretBox();
$message = 'Hello World!';
$key = $secretBox->generateKey();

$ciphertext = $secretBox->encrypt($message, $key);

echo $secretBox->decrypt($ciphertext, $key);

$secretBox->eraseData($key);
```

### Asymmetric block encryption

```php
use PetrKnap\CryptoSodium\Box;

$box = new Box();
$message = 'Hello World!';
$keyPair = $box->generateKeyPair();

$ciphertext = $box->encrypt($message, $keyPair);

echo $box->decrypt($ciphertext, $keyPair);

$box->eraseData($keyPair);
```

### Symmetric stream encryption

```php
use PetrKnap\CryptoSodium\SecretStream\XChaCha20Poly1305;
use PetrKnap\CryptoSodium\StreamTag;

$xChaCha20Poly1305 = new XChaCha20Poly1305();
$messageChunk1 = 'Hello ';
$messageChunk2 = 'World!';
$key = $xChaCha20Poly1305->generateKey();

$pushStream = $xChaCha20Poly1305->initPush($key);
$ciphertextHeader = $pushStream->header;
$ciphertextChunk1 = $pushStream->push($messageChunk1);
$ciphertextChunk2 = $pushStream->push($messageChunk2, tag: StreamTag::Final);

$pullStream = $xChaCha20Poly1305->initPull($ciphertextHeader, $key);
echo $pullStream->pull($ciphertextChunk1);
echo $pullStream->pull($ciphertextChunk2);

$xChaCha20Poly1305->eraseData($key);
```

### Symmetric block encryption with additional data

```php
use PetrKnap\CryptoSodium\Aead\Aes256Gcm;

$aes256Gcm = new Aes256Gcm();
$message = 'Hello World!';
$purpose = 'example';
$key = $aes256Gcm->generateKey();

$ciphertext = $aes256Gcm->encrypt($message, $key, additionalData: $purpose);

echo $aes256Gcm->decrypt($ciphertext, $key, additionalData: $purpose);

$aes256Gcm->eraseData($key);
```

---

Run `composer require petrknap/crypto-sodium` to install it.
You can [support this project via donation](https://petrknap.github.io/donate.html).
The project is licensed under [the terms of the `LGPL-3.0-or-later`](./COPYING.LESSER).
