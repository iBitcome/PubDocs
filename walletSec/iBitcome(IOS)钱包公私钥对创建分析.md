# iBitcome(IOS)钱包公私钥对创建分析


>**前言**:IOS采用了swift+Objective-C的方式开发，主要逻辑由swift实现，底层调用Objective-C。

## 助记词创建流程

为了方便我们从`BeeCoin.controllers.create_flow.create.CreateWalletUtil.swfit`的 `static func create(password: String) -> Wallet?`方法开始分析，开始几段代码是：

```
var network: BTCNetwork?
        var btcPath: String?
        var btcCoinType: Int?
        var isInTest = ENV.isDev || ENV.isTest || ENV.isPre
        if isInTest {
            network = BTCNetwork.testnet()
            btcPath = "m/44'/1'/0'/0/0"
            btcCoinType = 0
        }
        else {
            network = BTCNetwork.mainnet()
            btcPath = "m/44'/0'/0'/0/0"
            btcCoinType = 0
        }
```
从上面代码可以看到，主要是声明了路径btcPath、比特币类型btcCoinType以及根据网络类型主网和测试网络和对这几个变量进行赋值。

然后是和助记词产生相关代码：
```
guard let mnemonic = try! BIP39.generateMnemonics(bitsOfEntropy: 128) else { return nil }
        var seed = BIP39.seedFromMmemonics(mnemonic, password: "", language: BIP39Language.english)
```
从上面代码可以看到generateMnemonics函数根据长度128bit也就是16字节生成助记词，代码位于`Pods.web3swift.BIP39.swift`，函数代码实现如下：
```
static public func generateMnemonics(bitsOfEntropy: Int, language: BIP39Language = BIP39Language.english) throws -> String? {
        guard bitsOfEntropy >= 128 && bitsOfEntropy <= 256 && bitsOfEntropy % 32 == 0 else {return nil}
        guard let entropy = Data.randomBytes(length: bitsOfEntropy/8) else {throw AbstractKeystoreError.noEntropyError}
        return BIP39.generateMnemonicsFromEntropy(entropy: entropy, language: language)
        
    }
```
这里的语言选择已经写死为english，这里有个关系：

```
public enum BIP39Language {
    case english
    var words: [String] {
        switch self {
        case .english:
            return englishWords
        }
    }
}
```
有个枚举english，words在english的情况下，那么返回的是englishWords，而englishWords定义在`Pods.web3swift.BIP39+WordList.swift`，其实就是一个2048长度的字符串数组。

首先是一个长度判断bitsOfEntropy长度在128和256直接并且能够被32整除。

然后将长度带入到randomBytes函数生成熵entropy，此函数位于`Pods.web3swift.Data+Extension.swift`，代码实现如下：
```
public static func randomBytes(length: Int) -> Data? {
        var data = Data(count: length)
        for _ in 0...1024 {
            let result = data.withUnsafeMutableBytes {
                SecRandomCopyBytes(kSecRandomDefault, data.count, $0)
            }
            if result == errSecSuccess {
                return data
            }
        }
        return nil
    }
```
最终是调用苹果原生的SecRandomCopyBytes函数来生成随机byte数组。
回到generateMnemonics函数，将熵entropy和语言english带入调用generateMnemonicsFromEntropy函数，代码如下：
```
static public func generateMnemonicsFromEntropy(entropy: Data, language: BIP39Language = BIP39Language.english) -> String?  {
        guard entropy.count >= 16, entropy.count & 4 == 0 else {return nil}
        let checksum = entropy.sha256()
        let checksumBits = entropy.count*8/32
        var fullEntropy = Data()
        fullEntropy.append(entropy)
        fullEntropy.append(checksum[0 ..< (checksumBits+7)/8 ])
        var wordList = [String]()
        for i in 0 ..< fullEntropy.count*8/11 {
            guard let bits = fullEntropy.bitsInRange(i*11, 11) else {return nil}
            let index = Int(bits)
            guard language.words.count > index else {return nil}
            let word = language.words[index]
            wordList.append(word)
        }
        return wordList.joined(separator: " ")
    }
```
首先是判断熵的长度是否大于16并且饼干被4整除。
校验和checksum为熵的sha256值，这里的校验和比特位checksumBits为4。

然后随机产生从words这个字符串数组里面获取12个英语单词添加到wordList里面。

回到create函数，根据签名生成的助记词带入到BIP39的seedFromMmemonics函数生成种子，seedFromMmemonics函数代码实现如下：

```
static public func seedFromMmemonics(_ mnemonics: String, password: String = "", language: BIP39Language = BIP39Language.english) -> Data? {
        let valid = BIP39.mnemonicsToEntropy(mnemonics) != nil
        if (!valid) {
            print("Potentially invalid mnemonics")
        }
        guard let mnemData = mnemonics.decomposedStringWithCompatibilityMapping.data(using: .utf8) else {return nil}
        let salt = "mnemonic" + password
        guard let saltData = salt.decomposedStringWithCompatibilityMapping.data(using: .utf8) else {return nil}
        guard let seedArray = try? PKCS5.PBKDF2(password: mnemData.bytes, salt: saltData.bytes, iterations: 2048, keyLength: 64, variant: HMAC.Variant.sha512).calculate() else {return nil}
        let seed = Data(bytes:seedArray)
        return seed
    }
```
首先是根据助记词调用BIP39的mnemonicsToEntropy函数进行校验助记词是否合法，然后让助记词的decomposedStringWithCompatibilityMapping属性可以获取一个字符串mnemData，这个字符串的内容是使用Unicode范式D标准化获取的。

盐值salt为字符串mnemonic加password，这里的password为空。

同理根据decomposedStringWithCompatibilityMapping属性获取salt的saltData。

然后将上面几个参数带入到PBKDF2也就是调用PBKDF2的构造函数基于pbkdf2算法来生成种子序列。
最后将种子序列带入Data的构造函数返回一个seed对象。


## 公私钥对创建流程

接上一章节，继续回到create函数，在生成了助记词和基于助记词生成种子后，将种子和网络类型带入BTCKeychain到init函数返回kc对象。
```
guard let kc = BTCKeychain.init(seed: seed!, network: network!) else { return nil }
```
这里其实最终调用的是`Vender.CoreBitcoin.BTCKeychain.m`里面的initWithSeed函数，代码具体实现如下：

```
- (id) initWithSeed:(NSData*)seed network:(BTCNetwork*)network {
    if (self = [super init]) {
        if (!seed) return nil;

        NSMutableData* hmac = BTCHMACSHA512([@"Bitcoin seed" dataUsingEncoding:NSASCIIStringEncoding], seed);
        _privateKey = BTCDataRange(hmac, NSMakeRange(0, 32));
        _chainCode  = BTCDataRange(hmac, NSMakeRange(32, 32));
        BTCDataClear(hmac);

        _network = network;
    }
    return self;
}
```
代码很简单，和其他所有遵循BIP32协议的库一样，都是用种子seed，密钥`Bitcoin seed`根据HMACSHA512生成一个512长度也就是64字节的数组，然后左边的32字节作为私钥，右边的32字节作为chaincode，chaincode的左右在BIP32协议里面有明确的定义，这里不再做详细的解释。

>**说明**：CoreBitcoin是一个实现BIP39、BIP32、BIP44等的第三方库，在多个去中心化钱包的IOS版本上面都有使用。

回到create函数:

```
let d1 = BTCDataFromBase58Check(kc.extendedPrivateKey)! as Data
let d2 = kc.key.address.string.data(using: String.Encoding.utf8)
```
一看变量d1就是私钥，d2就是地址。

extendedPrivateKey函数位于`BTCKeychain.m`，具体的函数功能在里面说的很清楚：`Base58-encoded extended private key`。
BTCDataFromBase58Check函数定义在`CoreBitcoin.includes.BTCBase58.h`这个头文件，函数实现的功能在里面说的很清楚`Returns data for a Base58 string with checksum`。
这里的d1其实就是带有校验和的私钥。

`d2 = kc.key.address.string.data(using: String.Encoding.utf8)`，这里的key为kc对象里面的`@property(nonatomic, readonly) BTCKey* key;`，address为`@property(nonatomic, readonly) BTCPublicKeyAddress* address;`。
这里的address，在`BTCKey.h`里面已经说明：

```
// Public key hash.
// IMPORTANT: resulting address depends on whether `publicKeyCompressed` is YES or NO.
```


## 总结

通过分析生成助记词和公私钥对的代码，我们可以看到，对于实现助记词和私钥的BIP39和BIP32协议，采用的是开源第三方库CoreBitcoin。具体表现在：

- 助记词长度为12，且随机产生是使用了安全的随机数。并且助记词库具有2048个单词，已经足够强大和完备去对抗暴力破解。
- 助记词生成的种子Seed经过HmacSHA512算法得到数组的前32个字节作为私钥。
- 根据椭圆曲线为"secp256k1"的椭圆曲线算法使用私钥作为输入导出公钥。














































