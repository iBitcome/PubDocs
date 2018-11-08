# iBitcome(IOS)钱包keystore文件创建分析


## 前言

>关于keystore文件的介绍， 已经在[iBitcome(android)钱包keystore文件创建分析](./iBitcome\(android\)钱包keystore文件创建分析.md)介绍了，这里就不再做具体介绍。


## keystore文件创建过程分析

为了方便我们从`BeeCoin.controllers.create_flow.create.CreateWalletUtil.swfit`的 `static func create(password: String) -> Wallet?`方法开始分析，这个函数前面的几段代码在[iBitcome(IOS)钱包公私钥对创建分析](./iBitcome\(IOS\)钱包公私钥对创建分析.md)已经分析过，那么我们紧跟前面的分析继续查看create函数：

```
let ks = try! KeystoreWrapper.wrap(password, privatekeyData: d1, publicKey: d2, type: 1)
```
看代码就是猜测就是根据前面生成的私钥以及地址和输入的password调用wrap函数生成keystore对象ks，具体分析一下。

wrap函数位于`BeeCoin.customs.utils.HDWallet.KeystoreWrapper.swift`，具体代码实现如下：

```
func wrap(_ password: String, privatekeyData: Data?, publicKey: Data?, type: Int, dkLen: Int=32, N: Int = 4096, R: Int = 8, P: Int = 1) throws -> KeystoreParamsV3? {
        guard privatekeyData != nil, publicKey != nil else { throw KeystoreWrapperError.noDataError }
        do {
//            return try EthereumKeystoreV3.wrap(password, keyData: privatekeyData, publicKeyData: publicKey, type: type)
            return try EthereumKeystoreV3.wrap(password, keyData: privatekeyData, publicKeyData: publicKey, dkLen: dkLen, N: N, R: R, P: P, type: type)
        }
        catch {
            return nil
        }
    }
```
从上面代码看到最终是调用`EthereumKeystoreV3.wrap`函数，此函数位于`Pods.web3swift.EthereumKeystoreV3.swift`，具体的代码实现如下：

```
public class func wrap(_ password: String, keyData: Data?, publicKeyData: Data?, dkLen: Int=32, N: Int = 262144, R: Int = 8, P: Int = 1, type: Int) throws -> KeystoreParamsV3? {
        if (keyData == nil || publicKeyData == nil) {
            throw AbstractKeystoreError.encryptionError("Encryption without key data")
        }
        let saltLen = 32;
        guard let saltData = Data.randomBytes(length: saltLen) else {throw AbstractKeystoreError.noEntropyError}
        guard let derivedKey = scrypt(password: password, salt: saltData, length: dkLen, N: N, R: R, P: P) else {throw AbstractKeystoreError.keyDerivationError}
        let last16bytes = derivedKey[(derivedKey.count - 16)...(derivedKey.count-1)]
        let encryptionKey = derivedKey[0...15]
        guard let IV = Data.randomBytes(length: 16) else {throw AbstractKeystoreError.noEntropyError}
        let aecCipher = try? AES(key: encryptionKey.bytes, blockMode: .CTR(iv: IV.bytes), padding: Padding.noPadding)
        guard let encryptedKey = try aecCipher?.encrypt(keyData!.bytes) else {throw AbstractKeystoreError.aesError}
        let encryptedKeyData = Data(bytes:encryptedKey)
        var dataForMAC = Data()
        dataForMAC.append(last16bytes)
        dataForMAC.append(encryptedKeyData)
        let mac = dataForMAC.sha3(.keccak256)
        let kdfparams = KdfParamsV3(salt: saltData.toHexString(), dklen: dkLen, n: N, p: P, r: R, c: nil, prf: nil)
        let cipherparams = CipherParamsV3(iv: IV.toHexString())
        let crypto = CryptoParamsV3(ciphertext: encryptedKeyData.toHexString(), cipher: "aes-128-ctr", cipherparams: cipherparams, kdf: "scrypt", kdfparams: kdfparams, mac: mac.toHexString(), version: nil)
        let keystoreparams = KeystoreParamsV3(address: String.init(data: publicKeyData!, encoding: String.Encoding.utf8), crypto: crypto, id: UUID().uuidString.lowercased(), version: 3, type: type)
        return keystoreparams
    }
```
这里的`dkLen: dkLen, N: N, R: R, P: P`参数是实现scrypt算法的参数，具体意义这里不做介绍。

首先是一个私钥和地址是否为空的判断。

```
let saltLen = 32;
guard let saltData = Data.randomBytes(length: saltLen) else {throw AbstractKeystoreError.noEntropyError}
```
生成一个32字节长度的盐值随机数saltData。

`guard let derivedKey = scrypt(password: password, salt: saltData, length: dkLen, N: N, R: R, P: P) else {throw AbstractKeystoreError.keyDerivationError}`将输入password和盐值带入scrypt函数调用密钥导出算法scrypt生成导出密钥derivedKey，此函数位于`Pods.web3swift.CryptoExtensions.swift`，代码具体代码如下：

```
public func scrypt (password: String, salt: Data, length: Int, N: Int, R: Int, P: Int) -> Data? {
    let BytesMin = Int(crypto_generichash_bytes_min())
    let BytesMax = Int(crypto_generichash_bytes_max())
    if length < BytesMin || length > BytesMax {
        return nil
    }
    
    var output = Data(count: length)
    guard let passwordData = password.data(using: .utf8) else {return nil}
    let passwordLen = passwordData.count
    let saltLen = salt.count
    let result = output.withUnsafeMutableBytes { (outputPtr:UnsafeMutablePointer<UInt8>) -> Int32 in
        salt.withUnsafeBytes { (saltPointer:UnsafePointer<UInt8>) -> Int32 in
            passwordData.withUnsafeBytes{ (passwordPointer:UnsafePointer<UInt8>) -> Int32 in
                let res = crypto_pwhash_scryptsalsa208sha256_ll(passwordPointer, passwordLen,
                    saltPointer, saltLen,
                    UInt64(N), UInt32(R), UInt32(P),
                    outputPtr, length)
                return res
            }
        }
    }
    if result != 0 {
        return nil
    }
    return output
}

```
标准的算法，返回的应该是一个32字节的byte数组。

回到wrap函数，

```
let last16bytes = derivedKey[(derivedKey.count - 16)...(derivedKey.count-1)]
let encryptionKey = derivedKey[0...15]
```

加密密钥取的是encryptionKey的前面16个字节，last16bytes取的后面的16个字节。

`guard let IV = Data.randomBytes(length: 16) else {throw AbstractKeystoreError.noEntropyError}`生成16字节的iv向量。

`let aecCipher = try? AES(key: encryptionKey.bytes, blockMode: .CTR(iv: IV.bytes), padding: Padding.noPadding)`，将加密密钥encryptionKey，iv向量iv调用AES的init函数生成AES对象aecCipher，init函数代码如下：
```
public init(key: Array<UInt8>, blockMode: BlockMode, padding: Padding = .pkcs7) throws {
        self.key = Key(bytes: key)
        self.blockMode = blockMode
        self.padding = padding
    }
```
回到wrap函数，`guard let encryptedKey = try aecCipher?.encrypt(keyData!.bytes) else {throw AbstractKeystoreError.aesError}`通过aecCipher对象调用AES的加密函数encrypt对私钥keyData进行加密，encrypt代码如下：

```
public func encrypt(_ bytes: ArraySlice<UInt8>) throws -> Array<UInt8> {
        let chunks = bytes.batched(by: AES.blockSize)

        var oneTimeCryptor = try makeEncryptor()
        var out = Array<UInt8>(reserveCapacity: bytes.count)
        for chunk in chunks {
            out += try oneTimeCryptor.update(withBytes: chunk, isLast: false)
        }
        // Padding may be added at the very end
        out += try oneTimeCryptor.finish()

        if blockMode.options.contains(.paddingRequired) && (out.count % AES.blockSize != 0) {
            throw Error.dataPaddingRequired
        }

        return out
    }
```
很简单，AES的加密。

回到wrap函数，

```
let encryptedKeyData = Data(bytes:encryptedKey)
var dataForMAC = Data()
dataForMAC.append(last16bytes)
dataForMAC.append(encryptedKeyData)
let mac = dataForMAC.sha3(.keccak256)
```
代码很简单，把加密后的私钥encryptedKeyData生成Data对象，然后生成一个Data对象dataForMAC，然后把密码生成的last16bytes和秘文encryptedKeyData合并到一起进行sha3得到mac值。

`let kdfparams = KdfParamsV3(salt: saltData.toHexString(), dklen: dkLen, n: N, p: P, r: R, c: nil, prf: nil)`很简单，将盐值和kdf算法scrypt的各个参数调用KdfParamsV3的构造函数生成KdfParamsV3的对象kdfparams。

`let cipherparams = CipherParamsV3(iv: IV.toHexString())`带入IV向量生成CipherParamsV3对象cipherparams。

`let crypto = CryptoParamsV3(ciphertext: encryptedKeyData.toHexString(), cipher: "aes-128-ctr", cipherparams: cipherparams, kdf: "scrypt", kdfparams: kdfparams, mac: mac.toHexString(), version: nil)`将私钥秘文encryptedKeyData、cipher类型、cipherparams、kdf算法scrypt、kdfparams、mac调用CryptoParamsV3生成对象crypto。

`let keystoreparams = KeystoreParamsV3(address: String.init(data: publicKeyData!, encoding: String.Encoding.utf8), crypto: crypto, id: UUID().uuidString.lowercased(), version: 3, type: type)`最后将地址、crypto，keystore的id、版本号、类型调用KeystoreParamsV3的init函数生成对象keystoreparams，并且返回。

其实看到这里，wrap函数就是将密码、私钥、地址等调用此函数，根据keystore文件的结构类型抽象成一个个对象最终生成keystore的对象keystoreparams并且返回，最好在持久化的时候可以将keystoreparams直接序列化成json格式的文件。


## 总结

通过追踪代码分析keystore文件对象的整个生成过程，完全符合前面的关于keystore文件安全相关的介绍。说明iBitcome钱包IOS版本是严格按照keystore文件相关要求来生成的。







    


















