
# schnorrkel-java

Java implementation of the sr25519 signature algorithm (schnorr over ristretto25519). The existing rust implementation is [here](https://github.com/w3f/schnorrkel).

This library is currently able to create sr25519 keys, import sr25519 keys, and sign and verify messages. This version corresponds to [schnorrkel 0.1.1](https://docs.rs/schnorrkel/0.1.1/schnorrkel/)


### usage

Example: signing and verification

```java
import com.debuggor.schnorrkel.utils.HexUtils;

public class SignTest {

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = KeyPair.fromSecretSeed(HexUtils.hexToBytes("579d7aa286b37b800b95fe41adabbf0c2a577caf2854baeca98f8fb242ff43ae"));

        String payload = "000400ffa6158c2b928d5d495922366ad9b4339a023366b322fb22f4db12751e0ea93f5ca10fa50300005ffdae0956deb76e40b94af6e990717a7f8956a1920007739ff4b901f386";
        byte[] message = HexUtils.hexToBytes(payload);
        Signature signature = keyPair.sign(message);
        byte[] sign = signature.to_bytes();
        System.out.println(HexUtils.bytesToHex(sign));

        KeyPair fromPublicKey = KeyPair.fromPublicKey(keyPair.getPublicKey().toPublicKey());
        boolean verify = fromPublicKey.verify(message, sign);
        System.out.println(verify);
    }
}
```


### other 

[Go implementation](https://github.com/ChainSafe/go-schnorrkel)

Thanks to [@str4d](https://github.com/str4d) and [@isislovecruft](https://github.com/isislovecruft) for the open source [Curve25519 library](https://github.com/cryptography-cafe/curve25519-elisabeth/)






