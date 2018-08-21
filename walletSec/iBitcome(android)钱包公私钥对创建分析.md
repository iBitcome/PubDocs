# iBitcome(android)钱包公私钥对创建分析



## 助记词创建流程

为了方便我们从com.winway.bitcome.ui.hom.CreateWalletActivity的 createWallet方法开始分析，里面有一行是：

```
String v1 = v.a();

```
跟踪v.a方法，可以看到：

```

public static String a() {
    StringBuilder v0 = new StringBuilder();
    byte[] v1 = new byte[Words.TWELVE.byteLength()];
    new SecureRandom().nextBytes(v1);
    MnemonicGenerator v2 = new MnemonicGenerator(English.INSTANCE);
    v0.getClass();
    v2.createMnemonic(v1, w.a(v0));
    if(!v.a(v0.toString())) {
        return "";
    }

    return v0.toString();
}

```
从上面代码可以看到a函数是生成助记词字符串。

```
byte[] v1 = new byte[Words.TWELVE.byteLength()];
```

Words.TWELVE.byteLength()这里使用了novacrypto.github.io库的

```

static {
    Words.TWELVE = new Words("TWELVE", 0, 128);
    Words.FIFTEEN = new Words("FIFTEEN", 1, 160);
    Words.EIGHTEEN = new Words("EIGHTEEN", 2, 192);
    Words.TWENTY_ONE = new Words("TWENTY_ONE", 3, 224);
    Words.TWENTY_FOUR = new Words("TWENTY_FOUR", 4, 256);
    Words.$VALUES = new Words[]{Words.TWELVE, Words.FIFTEEN, Words.EIGHTEEN, Words.TWENTY_ONE, Words.TWENTY_FOUR};
}

private Words(String arg1, int arg2, int arg3) {
    super(arg1, arg2);
    this.bitLength = arg3;
}

public int byteLength() {
    return this.bitLength / 8;
}

```

从上面代码可以说明此助记词长度区间为12-24之间，这里本次钱包创建选择的助记词长度为12。
继续往下跟踪：

```

MnemonicGenerator v2 = new MnemonicGenerator(English.INSTANCE);
  
```
这里的枚举English实现了WordList借口，里面的定义了一个字符串数组words，长度为2048。说明里面有2048个英语单词。继续跟踪

```
v2.createMnemonic(v1, w.a(v0));
```

createMnemonic函数是quincysx库的函数，通过查看源代码可以看到：

```

public void createMnemonic(byte[] arg2, Target arg3) {
    int[] v2 = MnemonicGenerator.wordIndexes(arg2);
    try {
        this.createMnemonic(v2, arg3);
    }
    catch(Throwable v3) {
        Arrays.fill(v2, 0);
        throw v3;
    }

    Arrays.fill(v2, 0);
}

private void createMnemonic(int[] arg5, Target arg6) {
    String v0 = String.valueOf(this.wordList.getSpace());
    int v1;
    for(v1 = 0; v1 < arg5.length; ++v1) {
        if(v1 > 0) {
            arg6.append(((CharSequence)v0));
        }

        arg6.append(this.wordList.getWord(arg5[v1]));
    }
}

```

从上面代码可以看出是最终调用createMnemonic(int[] arg5, Target arg6)函数生成了助记词字符串。


## 公私钥对创建流程


接上一章节，继续跟踪createWallet方法：

```
String v9 = v.c(v1);

```
这里将vi即助记词字符串作为输入，根据跟踪v.c的函数的实现：

```
public static String c(String arg3) {
    byte[] v3 = new SeedCalculator().calculateSeed(arg3, "");
    String v0 = "";
    try {
        arg3 = ExtendedKey.create(v3).serialize(b.a() ^ 1);
    }
    catch(ValidationException v3_1) {
        goto label_17;
    }

    try {
        c.a(arg3);
        return arg3;
    }
    catch(ValidationException v0_1) {
        ValidationException v2 = v0_1;
        v0 = arg3;
        v3_1 = v2;
    }

label_17:
    v3_1.printStackTrace();
    return v0;
}

```
从上面代码可以看到v.c函数的实现。第一步：

```
byte[] v3 = new SeedCalculator().calculateSeed(arg3, "");
```
这里调用了novacrypto.github.io库的calculateSeed方法根据输入的助记词生成Seed种子。

继续查看下面一行代码：

```

arg3 = ExtendedKey.create(v3).serialize(b.a() ^ 1);

```

这里将前面生成的Seed种子作为create方法的入参数，create方法是com.quincysx.crypto库的方法，方法定义如下：

```

public static ExtendedKey create(byte[] seed) throws ValidationException {
    try {
        Mac mac = Mac.getInstance("HmacSHA512", "BC");
        SecretKey seedkey = new SecretKeySpec(BITCOIN_SEED, "HmacSHA512");
        mac.init(seedkey);
        byte[] lr = mac.doFinal(seed);
        byte[] l = Arrays.copyOfRange(lr, 0, 32);
        byte[] r = Arrays.copyOfRange(lr, 32, 64);
        BigInteger m = new BigInteger(1, l);
        if (m.compareTo(curve.getN()) >= 0) {
            throw new ValidationException("This is rather unlikely, but it did just happen");
        }
        ECKeyPair keyPair = new ECKeyPair(l, true);
        return new ExtendedKey(keyPair, r, 0, 0, 0);
    } catch (NoSuchAlgorithmException e) {
        throw new ValidationException(e);
    } catch (NoSuchProviderException e) {
        throw new ValidationException(e);
    } catch (InvalidKeyException e) {
        throw new ValidationException(e);
    }
}

```

如上面代码所示，首先根据输入的Seed种子经过HmacSHA512算法生成新的字节数组lr。这里的种子BITCOIN_SEED为

```
private static final byte[] BITCOIN_SEED = "Bitcoin seed".getBytes();

```


同时定义了2个字节数组l、r，l数组取的是lr数组的前面32个字节，r数组取的是lr数组的后面32个字节。请记住l和r数组，因为在后面创建ECKeyPair的时候要用到。

继续跟踪create方法的

```
ECKeyPair keyPair = new ECKeyPair(l, true);
```

进入到ECKeyPair可以看到

```
public ECKeyPair(byte[] p, boolean compressed) throws ValidationException {
    this(new BigInteger(1, p), compressed);
    if (!(p.length == 32 || p.length == 43 )) {
        throw new ValidationException("Invalid private key");
    }
}

```

从上面代码可以看到这个构造函数调用了另外的一个构造函数如下图所示：

```
public ECKeyPair(BigInteger priv, boolean compressed) {
    this.priv = priv;
    this.compressed = compressed;

    ECPoint multiply = CURVE.getG().multiply(priv);
    this.pub = multiply.getEncoded(false);
    this.pubComp = multiply.getEncoded(true);
}
```

从上面代码可以看到，私钥就是前面所提到的l数组，公钥匙是根据私钥基于椭圆曲线算法来得到：

```
ECPoint multiply = CURVE.getG().multiply(priv);
```

椭圆曲线算法是采用spongycastle这个JCE库，而spongycastle是专门为了android基于BouncyCastle改装的一个库。这里椭圆曲线是采用的是"secp256k1"。

```
protected static final X9ECParameters CURVE = SECNamedCurves.getByName("secp256k1");
```
最后create方法返回了

```
return new ExtendedKey(keyPair, r, 0, 0, 0);
```
根据ExtendedKey这个构造函数可以看到

```

public ExtendedKey(Key key, byte[] chainCode, int depth, int parent, int sequence) {
    this.master = key;
    this.chainCode = chainCode;
    this.parent = parent;
    this.depth = depth;
    this.sequence = sequence;
}

```
这里构造函数有5个参数，key即为前面创建的ECKeyPair,chainCode为前面生成的r数组，后面三个参数分别为0。

前面提到最后ExtendedKey类还有一个serialize(b.a() ^ 1)方法：

```
public String serialize(boolean production) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
        if (master.getRawPrivateKey() != null) {
            if (production) {
                out.write(xprv);
            } else {
                out.write(tprv);
            }
        } else {
            if (production) {
                out.write(xpub);
            } else {
                out.write(tpub);
            }
        }
        out.write(depth & 0xff);
        out.write((parent >>> 24) & 0xff);
        out.write((parent >>> 16) & 0xff);
        out.write((parent >>> 8) & 0xff);
        out.write(parent & 0xff);
        out.write((sequence >>> 24) & 0xff);
        out.write((sequence >>> 16) & 0xff);
        out.write((sequence >>> 8) & 0xff);
        out.write(sequence & 0xff);
        out.write(chainCode);
        if (master.getRawPrivateKey() != null) {
            out.write(0x00);
            out.write(master.getRawPrivateKey());
        } else {
            out.write(master.getRawPublicKey());
        }
    } catch (IOException e) {
    }
    return Base58Check.bytesToBase58(out.toByteArray());
}
```
如上代码所示，这个函数无非就是根据输入的bool变量来确定最后输出的是Base58后的公钥还是私钥。

## 总结

通过分析生成助记词和公私钥对的代码，我们可以看到：

- 助记词长度为12，且随机产生是使用了安全的随机数。并且助记词库具有2048个单词，已经足够强大和完备去对抗暴力破解。
- 助记词生成的种子Seed经过HmacSHA512算法得到数组的前32个字节作为私钥。
- 根据椭圆曲线为"secp256k1"的椭圆曲线算法使用私钥作为输入导出公钥。














































