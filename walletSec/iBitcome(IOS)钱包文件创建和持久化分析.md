# iBitcome(IOS)钱包文件创建和持久化分析


## 前言

>关于助记词到私钥生成的分析请参考[iBitcome(IOS)钱包公私钥对创建分析](./iBitcome\(IOS\)钱包公私钥对创建分析.md)

>关于keystore对象生成的分析请参考[iBitcome(IOS)钱包keystore文件创建分析](./iBitcome\(IOS\)钱包keystore文件创建分析.md)


## keystore文件持久化过程分析

为了方便我们从`BeeCoin.controllers.create_flow.create.CreateWalletUtil.swfit`的 `static func create(password: String) -> Wallet?`方法开始分析，这个函数前面的几段代码在[iBitcome(IOS)钱包公私钥对创建分析](./iBitcome\(IOS\)钱包公私钥对创建分析.md)和keystore对象生成[iBitcome(IOS)钱包keystore文件创建分析](./iBitcome\(IOS\)钱包keystore文件创建分析.md)已经分析过，那么我们紧跟前面的分析继续查看create函数：
在生成了keystore对象以后，


```
let wallet = Wallet()
wallet.address = ""
wallet.publicKey = kc.extendedPublicKey

```
首先是实例化一个Wallet对象wallet，然后对wallet对象里面对属性进行赋值。

>**说明**：这里的wallet对象里面每个属性的意义，查看Wallet所在的地方`BeeCoin.models.db.Wallet.swfit`。

这里对公钥publicKey根据前面生成对kc对象调用函数extendedPublicKey函数，extendedPublicKey函数位于`Vender.CoreBitcoin.BTCKeychain.m`，说明也是Objective-C实现的底层函数，通过跟踪代码，其实就是根据椭圆曲线secp256k1由私钥导出公钥。

```
let epkh256 = BTCHash256(wallet.publicKey!.data(using: String.Encoding.utf8))! as Data
wallet.remoteWalletKey = RIPEMD160.hash(message: epkh256).toHexString()
wallet.createDate = NSDate.jl_currentTimeString(withType: JLDateFormat.asia)
wallet.type = 0
```
上面代码很简单，将公钥进行sha256然后rip160得到的一个key叫remoteWalletKey。创建钱包的生成时间以及钱包类型为0，即是HD钱包。
```
wallet.encryptMnemonic  = try! AES(key: Padding.zeroPadding.add(to: password.bytes, blockSize: AES.blockSize), blockMode: BlockMode.ECB).encrypt(mnemonic.bytes).toBase64()
```
上面代码就是将助记词用输入password作为加密密钥输入进行aes加密得到加密后的助记词encryptMnemonic。
```
wallet.iconID = Int(arc4random()%20)+1
wallet.keystore = String(data: try! JSONEncoder().encode(ks), encoding: String.Encoding.utf8)
wallet.isAutoIncrement = true
wallet.isDeleted = true//待全部数据准备好，再变为false
wallet.passwordVersion = 0
wallet.tokenStr = "BTC|BCH|ETH"
wallet.name = "wallet-0\(DB.shareInstance().getWallets()!.count+1)"
wallet.passwordHash = password.sha3String()
wallet.dataVersion = 2
```
上面代码也很简单，这里有两个重点一个是会将前面生成keystore对象ks序列化成json格式的字符串，另外一个是将授权口令进行SHA3得到一个口令的哈希值。

```
let kc1 = kc.derivedKeychain(withPath: "m/44'/\((ENV.isDev || ENV.isTest || ENV.isPre) ? 1 : 0)'/0'")!
let kc2 = kc.derivedKeychain(withPath: "m/44'/\((ENV.isDev || ENV.isTest || ENV.isPre) ? 1 : 0)'/1'")!
wallet.BTCAccount = kc1.extendedPublicKey + "|" + kc2.extendedPublicKey
let kc3 = kc.derivedKeychain(withPath: "m/44'/145'/0'")!
let kc4 = kc.derivedKeychain(withPath: "m/44'/145'/1'")!
wallet.BCHAccount = kc3.extendedPublicKey + "|" + kc4.extendedPublicKey
```
很简单，根据前面生成的主kc对象根据不同币种的不同路径调用derivedKeychain函数生成不同币种的kc对象，并且导出扩展公钥赋值给wallet的属性BTCAccount和BCHAccount。

```
DB.shareInstance().addWallet(wallet)
wallet.identifier = Int(wallet.lastInsertedRowID)
dPrint("id: \(wallet.identifier ?? 000) 创建成功")
dPrint("wallet \(Date.nowMS())")

```
看代码就是持久化保持钱包信息，主要分析一下addWallet函数，addWallet函数位于`BeeCoin.models.db.DB.swift`，主要代码实现如下：
```
func addWallet(_ wallet: Wallet) -> Void {
        try? database?.insert(objects: wallet, intoTable: walletTable)
    }
```
database来自于：

```
func boot() -> Void {
        guard database == nil else { return }
        let userDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]
        var path = userDir + "/ bcdb/wallet.db"
        if ENV.isOnline {
            path = userDir + "/bcdbmainnet/wallet.db"
        }
        database = Database(withPath: path)
        database!.setCipher(key: "yBDFu3Cf5SzcYb2yojhckyTID0".data(using: String.Encoding.ascii))
        try? database!.create(table: userTable, of: User.self)
        try? database!.create(table: walletTable, of: Wallet.self)
        try? database!.create(table: HDAddressTable, of: HDAddress.self)
        try? database!.create(table: dataCacheTable, of: DataCache.self)
        
        if getUser() == nil {
            let user = User()
            try? database?.insert(objects: user, intoTable: userTable)
        }
        
        if getDataCache() == nil {
            let dataCache = DataCache()
            try? database?.insert(objects: dataCache, intoTable: dataCacheTable)
        }
    }
```
看起来很简单，这是一个WCDB，即是开源的微信的终端数据库，直接调用就好了，具体的接口调用请参考官方文档。

从这个函数开源看到db文件的主路径代码是`let userDir = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)[0]`，其实就是app的私有目录路径。


以及在设置Cipher的时候setCipher设置了加密功能，这个密钥是硬编码到代码的，目前为`yBDFu3Cf5SzcYb2yojhckyTID0`。

回到addWallet函数，其实就是调用了insert方法把wallet这个对象插入到WCDB了，插入的table初始化在init函数里面`walletTable = "walletInfoTable"`。

回到创建钱包的create函数，在插入钱包以后identifier这个值目前为0，同时打印此id以及创建成功标志。继续往下看代码，前面的都是处理HD钱包的master公私钥和地址等相关部分，下来代码来处理钱包的BTC部分：

```
let btcKey = kc.key(withPath: btcPath!)
let btcStore = HDAddress()
btcStore.masterWalletID = wallet.lastInsertedRowID
btcStore.publicKey = btcKey!.compressedPublicKeyAddress.string
btcStore.publicHash = (BTCDataFromBase58Check(btcKey!.address.string) as Data).dropFirst().toHexString()
btcStore.tokenName = "BTC"
btcStore.cointype = btcCoinType
btcStore.path = btcPath
if isInTest {
    btcStore.address = btcKey!.addressTestnet.string
}
else {
    btcStore.address = btcKey!.address.string
}
btcStore.createDate = NSDate.jl_currentTimeString(withType: JLDateFormat.asia)
btcStore.passwordVersion = 0
DB.shareInstance().addHDAddress(btcStore)
dPrint("btc \(Date.nowMS())")
```
看上面代码，masterkc根据btc路径导出btc的btcKey对象，实例化一个HDAddress对象btcStore，然后对btcStore封装属性对值，很简单就不一一解释了。最后还是调用WCDB的addHDAddress方法将btcStore存储到db文件里面，具体代码如下：

```
func addHDAddress(_ address: HDAddress) -> Void {
        try? database?.insert(objects: address, intoTable: HDAddressTable)
    }
```
这里到HDAddressTable为`let HDAddressTable = "HDAddressTable"`。

回到创建钱包的create函数，继续走到了BCH的部分：

```
let bchKey = kc.key(withPath: "m/44'/145'/0'/0/0")
let bchStore = HDAddress()
bchStore.masterWalletID = wallet.lastInsertedRowID
bchStore.publicKey = bchKey!.compressedPublicKeyAddress.string
bchStore.publicHash = (BTCDataFromBase58Check(bchKey!.address.string) as Data).dropFirst().toHexString()
bchStore.tokenName = "BCH"
bchStore.cointype = 145
bchStore.path = "m/44'/145'/0'/0/0"
if isInTest {
    bchStore.address = bchKey!.addressTestnet.string
    bchStore.BCHAddress = AddressFormatter.format((BTCDataFromBase58Check(bchStore.address) as Data).dropFirst().toHexString(), type: AddressFormatter.BTCAddressType.P2PKH_test, bchType:AddressFormatter.BCHType.reg)
    if ENV.isPre || ENV.isTest {
        bchStore.BCHAddress = AddressFormatter.format((BTCDataFromBase58Check(bchStore.address) as Data).dropFirst().toHexString(), type: AddressFormatter.BTCAddressType.P2PKH_test, bchType:AddressFormatter.BCHType.test)
    }
}
else {
    bchStore.address = bchKey!.address.string
    bchStore.BCHAddress = AddressFormatter.format((BTCDataFromBase58Check(bchStore.address) as Data).dropFirst().toHexString(), type: AddressFormatter.BTCAddressType.P2PKH, bchType:AddressFormatter.BCHType.main)
    if ENV.isPre || ENV.isTest {
        bchStore.BCHAddress = AddressFormatter.format((BTCDataFromBase58Check(bchStore.address) as Data).dropFirst().toHexString(), type: AddressFormatter.BTCAddressType.P2PKH_test, bchType:AddressFormatter.BCHType.test)
    }
}
bchStore.createDate = NSDate.jl_currentTimeString(withType: JLDateFormat.asia)
bchStore.passwordVersion = 0
DB.shareInstance().addHDAddress(bchStore)
dPrint("bch \(Date.nowMS())")
```
流程基本上和BTC的流程一模一样，也是实例化一个HDAddress的对象bchStore，然后对bchStore的属性例如公钥、地址、路径等信息进行封装，然后调用WCDB的addHDAddress方法将bchStore保持到db文件里面。

create函数的最后部分是处理钱包的ETH部分，代码如下：
```
var originPrivateKey = (kc.derivedKeychain(withPath: "m/44'/60'/0'/0/0").key.privateKey! as Data)
let ethKey = try! EthereumKeystoreV3.init(privateKey: originPrivateKey, password: password)
defer { Data.zero(&originPrivateKey) }
let ethStore = HDAddress()
ethStore.masterWalletID = wallet.lastInsertedRowID
ethStore.tokenName = "ETH"
ethStore.cointype = 60
ethStore.path = "m/44'/60'/0'/0/0"
ethStore.address = ethKey?.addresses?.first?.address
ethStore.publicHash = ethKey?.addresses?.first?.address.substring(s: 2, e: ethKey?.addresses?.first?.address.length())?.lowercased()
ethStore.keystore = String(data: try! JSONEncoder().encode(ethKey?.keystoreParams), encoding: String.Encoding.utf8)
ethStore.createDate = NSDate.jl_currentTimeString(withType: JLDateFormat.asia)
ethStore.passwordVersion = 0
DB.shareInstance().addHDAddress(ethStore)
dPrint("eth \(Date.nowMS())")
```
从上面代码可以看到这个和前面处理BTC和BCH流程只基本一致，不同的是这里会存储ETH的keystore文件。

因此首先是kc对象调用derivedKeychain函数根据ETH的路径导出ETH的originPrivateKey。

然后将调用EthereumKeystoreV3的init函数：
```
public init? (privateKey: Data, password: String = "BANKEXFOUNDATION") throws {
        guard privateKey.count == 32 else {return nil}
        guard SECP256K1.verifyPrivateKey(privateKey: privateKey) else {return nil}
        try encryptDataToStorage(password, keyData: privateKey)
    }
```
传入私钥和授权口令，此函数首先是验证私钥是否校验通过，然后调用encryptDataToStorage函数，此函数如下：
```
public func encryptDataToStorage(_ password: String, keyData: Data?, dkLen: Int=32, N: Int = 4096, R: Int = 8, P: Int = 1) throws {
        if (keyData == nil) {
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
        guard let pubKey = Web3.Utils.privateToPublic(keyData!, compressed: true) else {throw AbstractKeystoreError.keyDerivationError}
        pubKeyHex = pubKey.toHexString()
        guard let addr = Web3.Utils.publicToAddress(pubKey) else {throw AbstractKeystoreError.keyDerivationError}
        self.address = addr
        let keystoreparams = KeystoreParamsV3(address: addr.address.lowercased(), crypto: crypto, id: UUID().uuidString.lowercased(), version: 3)
        self.keystoreParams = keystoreparams
    }
```
很简单，其实就是生成了ETH的keystore对象keystoreparams并且返回。

因此回到create函数，在处理ETH的时候，就有`ethStore.keystore = String(data: try! JSONEncoder().encode(ethKey?.keystoreParams), encoding: String.Encoding.utf8)`，就是把keystoreParams序列化成json格式的字符串。

最后同样调用addHDAddress函数将ETH的ethStore对象保持到db文件。

>从保存BTC、BCH、ETH三个币种的钱包处理流程可以看到，这里只有ETH保存了对应币种的keystore文件，开发解释是因为做eth的时候不是HD钱包，没有主扩展私钥的概念。后面加的hd钱包，没改之前的逻辑。

回到创建钱包的create函数，最后是：

```
//生成USDT地址(如果有必要的话)        
USDTAddressUtil.syncAddressesFromBTC(inWallet: wallet)
//生成WHC地址(如果有必要的话)
WHCAddressUtil.syncAddressesFromBCH(inWallet: wallet)
```
看代码就是生成usdt和whc的地址。

最后把wallet对象返回。


到这里钱包的创建过程就分析完了。









    


















