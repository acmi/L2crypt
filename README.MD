L2crypt
=======
![GitHub](https://img.shields.io/github/license/acmi/l2crypt)
[![](https://jitpack.io/v/acmi/l2crypt.svg)](https://jitpack.io/#acmi/l2crypt)

An open source library in Java for encryption/decryption Lineage 2 files.

Supported headers: 111, 120, 121, 211, 212, 41x, l2encdec(41x), lamecrypt(811, 820, 821, 911, 912, 61x)

Usage
-------
```
File cryptedFile = ...
File destFile = ...

try(InputStream is = L2Crypt.getInputStream(cryptedFile);
	OutputStream os = new FileOutputStream(destFile)){
	byte[] buffer = new byte[0x1000];
	int r;
	while ((r = is.read(buffer)) != -1){
		os.write(buffer, 0, r);
	}
}
```

Maven
-----
```maven
<repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
</repository>

<dependency>
    <groupId>com.github.acmi</groupId>
    <artifactId>l2crypt</artifactId>
    <version>1.3.3</version>
</dependency>
```

Gradle
------
```gradle
repositories {
    // ...
    maven { url 'https://jitpack.io' }
}

dependencies {
    compile group:'com.github.acmi', name:'l2crypt', version: '1.3.3'
}
```

Credits
-------
* The Legion of the Bouncy Castle for Blowfish Engine that is part of the [BouncyCastle JCE]
* DStuff for l2encdec
* Hint for 41x cipher

License
-------
*L2crypt* is open source licensed under the [MIT License](LICENSE)

[BouncyCastle JCE]: https://github.com/bcgit/bc-java