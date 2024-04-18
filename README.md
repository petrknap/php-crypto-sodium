# Crypto Sodium

A simple library that packages functional `sodium_crypt_*` into objects.

Inputs and outputs are binary data, don't be afraid to use the [petrknap/binary](../php-binary).


## Examples

### Authenticated symmetric encryption

```php
use PetrKnap\CryptoSodium\SecretBox;

$secretBox = new SecretBox();
$message = 'Hello World!';
$key = $secretBox->generateKey();
$ciphertext = $secretBox->encrypt($message, $key);

var_dump($message === $secretBox->decrypt($ciphertext, $key));

$secretBox->eraseData($key);
```

---

Run `composer require petrknap/crypto-sodium` to install it.
You can [support this project via donation](https://petrknap.github.io/donate.html).
The project is licensed under [the terms of the `LGPL-3.0-or-later`](./COPYING.LESSER).
