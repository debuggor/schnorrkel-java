
# schnorrkel-java

Java implementation of the sr25519 signature algorithm (schnorr over ristretto25519). The existing rust implementation is [here](https://github.com/w3f/schnorrkel).

This library is currently able to create sr25519 keys, import sr25519 keys, and sign and verify messages. 


### usage

Example: signing and verification

```java
import com.debuggor.schnorrkel.utils.HexUtils;

public class SignTest {

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = KeyPair.fromSecretSeed(HexUtils.hexToBytes("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"), ExpansionMode.Ed25519);

        byte[] message = "test message".getBytes();
        SigningContext ctx = SigningContext.createSigningContext("good".getBytes());
        SigningTranscript t = ctx.bytes(message);
        Signature signature = keyPair.sign(t);
        byte[] sign = signature.to_bytes();
        System.out.println(HexUtils.bytesToHex(sign));


        SigningContext ctx2 = SigningContext.createSigningContext("good".getBytes());
        SigningTranscript t2 = ctx2.bytes(message);
        KeyPair fromPublicKey = KeyPair.fromPublicKey(keyPair.getPublicKey().toPublicKey());
        boolean verify = fromPublicKey.verify(t2, sign);
        System.out.println(verify);
    }
}
```


### other 

[Go implementation](https://github.com/ChainSafe/go-schnorrkel)

Thanks to [@str4d](https://github.com/str4d) and [@isislovecruft](https://github.com/isislovecruft) for the open source [Curve25519 library](https://github.com/cryptography-cafe/curve25519-elisabeth/)






