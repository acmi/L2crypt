L2crypt
=======
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
    <id>l2crypt-github</id>
    <url>https://raw.githubusercontent.com/acmi/L2crypt/mvn-repo</url>
</repository>

<dependency>
    <groupId>acmi.l2.clientmod</groupId>
    <artifactId>l2crypt</artifactId>
    <version>1.2</version>
</dependency>
```

Gradle
------
```gradle
repositories {
    // ...
    maven { url "https://raw.githubusercontent.com/acmi/L2crypt/mvn-repo" }
}

dependencies {
    compile group:'acmi.l2.clientmod', name:'l2crypt', version: '1.2'
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