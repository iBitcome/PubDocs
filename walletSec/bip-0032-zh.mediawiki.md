*本文翻译自：[https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)。
为了使语句表达更加贴切，个别地方未按照原文逐字逐句翻译，如有出入请以原文为准。*

最近的变化：

* （2013-4-16）增加了i ≥ 0x80000000的私有派生（减少了父私钥的泄漏）
* （2013-4-30）从与IL相乘切换到IL相加（更快，更容易实现）
* （2013-5-25）增加测试向量。
* （2014-1-15）对索引i ≥ 0x80000000的密钥重命名到增强型密钥，并且添加了显式转换函数。
* （2017-2-24）添加了针对增强型密钥的leading zeros的测试向量。

```
  BIP: 32
  Layer: Applications
  Title: Hierarchical Deterministic Wallets
  Author: Pieter Wuille <pieter.wuille@gmail.com>
  Comments-Summary: No comments yet.
  Comments-URI: [https://github.com/bitcoin/bips/wiki/Comments:BIP-0032](https://github.com/bitcoin/bips/wiki/Comments:BIP-0032)
  Status: Final
  Type: Informational
  Created: 2012-02-11
  License: BSD-2-Clause
```

# 摘要

该文档描述了分层确定性钱包（或“HD钱包”）：HD钱包可以部分或完全共享给不同的系统，以及每个有或没有能力消费币。

该规范旨在为可在不同客户端之间互换的确定性钱包设置标准。虽然这里描述的钱包有很多特点，但并非所有都需要支持客户端。 

该规范由两部分组成。在第一部分中，提出了一种从单个种子派生出树形的密钥对系统。第二部分演示了如何在这种树的顶部构建钱包结构。


# 版权

这个BIP是在2条款BSD许可下授权的。

# 目的

比特币参考客户端使用随机生成的密钥。为了避免在每个交易之后进行备份的必要性（默认情况下）100个密钥缓存在一个预留密钥池中。然而，这些钱包并不意图在多个系统上同时共享和使用。 他们支持通过使用钱包加密功能隐藏他们的私钥并且不公开密码，但这样的“中性”钱包也失去了生成公钥的权力。

确定性钱包不需要这种频繁的备份，椭圆曲线数学允许可以在不显示私钥的情况下计算公钥的方案。 这允许例如网上商店让网络服务器为每个订单或每个客户生成新的地址（公钥哈希），而不使网络服务器访问相应的私钥（花费收到的资金需要私钥）。

然而，确定性钱包通常由一个密钥对“链”组成。只有一条链就意味着共享一个钱包是全无差异的。 然而，在某些情况下，只有一些（公开）密钥才能被共享和可恢复。在网上商店的例子中，网络服务器不需要访问商家钱包的所有公钥;仅用于用于接收客户付款的那些地址，而不是例如商家花钱产生的更改地址。分层确定性钱包允许通过支持从单个根导出的多个密钥对链来进行这种选择性共享。

# 详细说明：密钥派生

## 协议

在本文的其余部分中，我们将假设比特币中使用的公钥密码算法，即使用SEC2525K1定义的字段和曲线参数的椭圆曲线密码算法（[http://www.SEG.org/SEC2-v2.pdf](http://www.SEG.org/SEC2-v2.pdf)。
变量如下：

* 整数模数曲线的顺序（简称n）。

* 曲线上的点坐标。

* 字节序列。

两个坐标对的加法（+）定义为EC组操作的应用。连接（||）是将一个字节序列附加到另一个字节序列的操作。

作为标准转换函数，我们假设：

* point（p）：返回由整数p表示的secp256k1基点的EC点乘法（EC组操作的重复应用）产生的坐标对。

* ser32（i）：将32位无符号整数i序列化为4字节序列，大端存储(计算机术语)。

* ser256（p）：将整数p序列化为32字节序列，大端存储(计算机术语)。

* serP（P）：使用SEC1的压缩格式将坐标对P=（x，y）串行化为字节序列：（0x02或0x03）|| ser256（x），其中头字节取决于省略的y坐标的奇偶校验。

* parse256（p）：将32字节序列转换为256位数，大端存储(计算机术语)。

## 扩展密钥

接下来，我们将定义一个从父密钥导出多个子密钥的函数。为了防止这些仅仅依赖于密钥本身，我们首先使用额外的256位熵来扩展私钥和公钥。称为链码的扩展对于相应的私钥和公钥是相同的，由32个字节组成。

我们将扩展私钥表示为（k，c），k为普通私钥，c为链码。 扩展公钥表示为（K，c），K = point（k），c表示链码。

每个扩展密钥有 2^31 个普通子密钥，2^31个增强子密钥。 这些子密钥都有一个索引。 普通子密钥使用索引0到2^31-1。 增强子密钥使用索引 2^31 到 2^32-1。 为了简化增强密钥索引的符号，数字iH表示i + 2^31。

## 子密钥推导（CKD）函数

给定父扩展密钥和索引i，可以计算相应的子扩展密钥。这样做的算法取决于子密钥是否是增强密钥（或等效地，i是否≥2^31），包括私钥和公钥。

**父私钥 → 子私钥**

函数CKDpriv（（kpar，cpar），i）→（ki，ci）从父扩展私钥计算子扩展私钥：

    检查 是否 i ≥ 2^31(子私钥是否是增强密钥)。

    如果是（增强子密钥）：让I= HMAC-SHA512（Key = cpar，Data = 0x00 || ser256（kpar）|| ser32（i））。 （注意：0x00将私钥补齐到33字节长。）

    如果不是（普通的普通子密钥）：让I= HMAC-SHA512（Key = cpar，Data = serP（point（kpar））|| ser32（i））。

    将I分为两个32字节序列，IL和IR。

    返回的子密钥ki是parse256（IL）+ kpar（mod n）。

    返回的链码ci是IR。

    如果parse256（IL）≥n或ki = 0，则生成的密钥无效，并且应继续下一个i值。 （注：概率低于1/2127）

HMAC-SHA512功能在RFC 4231中规定。

**父公钥 → 子公钥**

函数CKDpub（（Kpar，cpar），i）→（Ki，ci）从父扩展公钥计算子扩展公钥。它只针对非增强的子密钥定义。

    检查是否 i ≥ 2^31 (子密钥是否是增强密钥)

    如果是(增强子密钥)：返回失败

    如果不是(普通子密钥):让I= HMAC-SHA512(Key = cpar, Data = serP(Kpar) || ser32(i)).

    将I分为两个32字节序列，IL和IR。

    返回的子密钥Ki是point（parse256（IL））+ Kpar。

    返回的链码ci是IR。

    如果parse256（IL）≥n或Ki是无限远的点，则生成的密钥无效，并且应继续下一个i值。

**父私钥 → 子公钥**

函数N（（k，c））→（K，c）计算与扩展私钥对应的扩展公钥（“中和”版本，因为它消除了签署交易的能力）。

    返回的密钥K是point（k）。

    返回的链码c只是传递的链码。

要计算父私钥的公用子密钥：

    N（CKDpriv（（kpar，cpar），i））（总是工作）。

    CKDpub（N（kpar，cpar），i）（仅适用于非增强子密钥）。

它们等价的事实是使非增强密钥有用（可以在不知道任何私钥的情况下导出给定父密钥的子公钥），以及它们与增强密钥的区别。 不总是使用非增强密钥（更有用）的原因是安全性; 后面可以了解更详细的信息。

**父公钥 → 子私钥**

不可能发生

## 密钥树结构

下一步是级联几个CKD结构来构建树。我们从一个root开始，主扩展密钥m。通过对i的几个值评估CKDpriv（m，i），我们得到了多个1级派生节点。由于这些都是扩展密钥，所以也可以应用CKDpriv。

为了缩短符号，

我们将写入CKDpriv（CKDpriv（m，3H），2），5）作为m / 3H / 2/5。等同于公钥，

我们写入CKDpub（CKDpub（M，3），2），5）作为M / 3/2/5。

这导致以下身份：

1、 N（m / a / b / c）= N（m / a / b）/ c = N（m / a）/ b / c = N（m）/ a / b / c = M / a / b / C。  
2、 N（m / aH / b / c）= N（m / aH / b）/ c = N（m / aH）/ b / c。

然而，N（m / aH）不能被重写为N（m）/ aH，因为后者是不可能的。
树中的每个叶节点对应于实际密钥，而内部节点对应于从它们分散的密钥的集合。叶节点的链码被忽略，只有它们嵌入的私钥或公钥是相关的。由于这种结构，知道扩展私钥允许重构所有后代私钥和公钥，并且知道扩展公钥允许重建所有后代非增强公钥。

## 密钥标识符

扩展密钥可以由序列化的ECSDA公钥K的Hash160（SHA256之后的RIPEMD160）标识，忽略链码。 这完全对应于传统比特币地址中使用的数据。不建议以base58格式表示此数据，因为它可能被解释为一种地址（并且钱包软件不需要接受对链密钥本身的支付）。

标识符的前32位称为密钥指纹。

## 序列化格式

扩展的公钥和私钥如下序列化：

- 4字节：版本字节（mainnet：0x0488B21E public，0x0488ADE4 private; testnet：0x043587CF public，0x04358394 private）

- 1字节：深度：主节点为0x00，级别1派生密钥为0x01。

- 4字节：父密钥的指纹（如果主密钥为0x00000000）

- 4字节：子数字。这是对于i在xi = xpar / i中的ser32（i），其中xi是键序列化。 （如果主密钥为0x00000000）

- 32字节：链码

- 33字节：公钥或私钥数据（公钥的serP（K），私钥的0x00 || ser256（k））

可以通过首先添加32个校验和位（从双SHA-256校验和派生），然后转换为Base58表示，可以像Base58中的其他Bitcoin数据一样对78字节结构进行编码。这会导致最多112个字符的Base58编码的字符串。由于可选择版本字节，Base58表示将以“net”，“net”，“tpv”或“tpub”为起始的“xprv”或“xpub”开头。

请注意，父指纹仅作为在软件中检测父节点和子节点的快速方式，软件必须愿意处理冲突。在内部，可以使用完整的160位标识符。

导入序列化扩展公钥时，实现必须验证公钥数据中的X坐标是否对应于曲线上的一个点。如果不是，扩展的公钥是无效的。

## 主密钥生成

可能的扩展密钥对的总数几乎为2^512，但生成的密钥只有256位长，在安全性方面提供约一半的密钥。 因此，主密钥不是直接生成，而是从潜在的短种子值生成。

- 从（P）RNG生成所选长度（128到512位;建议256位）的种子字节序列S。

- 计算I = HMAC-SHA512（Key =“Bitcoin seed”，Data = S）

- 将I分为两个32字节序列，IL和IR。

- 使用parse256（IL）作为主密钥，IR作为主链码。

如果IL为0或≥n，则主密钥无效。

![](https://github.com/bitcoin/bips/blob/master/bip-0032/derivation.png)

# 详细说明:钱包结构

前面的部分指定了关键树及其节点。下一步是在这棵树上施加钱包结构。本节中定义的布局是仅默认的，客户端要求具备兼容性，即使不支持所有功能。

## 缺省的钱包结构

HDW被组织为几个“帐户”。 帐号已编号，默认帐号（“”）为数字0.客户端不需要支持多个帐户 - 如果不是，则只使用默认帐户。

每个帐户由两个密钥链组成：内部和外部链。 外部密钥链用于生成新的公共地址，而内部密钥链用于所有其他操作（更改地址，生成地址…，任何不需要传达的内容）。 不支持单独的密钥链的客户端应该使用外部的一个。

m / iH / 0 / k对应于从主站m导出的HDW的帐号i的外部链的第k个密钥对。
m / iH / 1 / k对应于从主站m导出的HDW的帐号i的内部链的第k个密钥。

## 示例

全钱包分享：m

在两个系统需要访问单个共享钱包的情况下，并且都需要能够执行花费的情况下，需要共享主专用扩展密钥。节点可以保留为外部链条缓存的N个预先密钥池，以监听收到的付款。内部链条的前瞻性可能非常小，因为这里不可能有任何差距。对于第一个未使用的帐户的链，额外的预览可能是活动的 - 在使用时触发新帐户的创建。请注意，帐户的名称仍然需要手动输入，无法通过块链同步。

审核：N（m / *）

如果审核员需要完全访问传入和传出付款列表，则可以共享所有帐户公用扩展密钥。这将允许审核员在所有帐户中查看和从钱包中获得的所有交易，但不能查看单个保密密钥。

每-办公室余额：m / iH

当一家企业有几个独立的办公室时，他们都可以使用从一个主人那里获得的钱包。这将允许总部维持一个超级钱包，看到所有办公室的所有进出口交易，甚至允许在办公室之间移动资金。

经常性企业对企业交易：N（m / iH / 0）

如果两个业务伙伴经常转账，可以将特定账户的外部链（M / ih / 0）的扩展公钥用作“超级地址”，允许频繁的交易（不容易）相关联，但不需要为每个付款请求一个新的地址。这种机制也可以被矿井运营商用作可变支付地址。

不安全的收款人：N（m / iH / 0）

当使用不安全的网络服务器来运行电子商务网站时，需要知道用于接收付款的公共地址。网络服务器只需要知道单个帐户的外部链路的公共扩展密钥。这意味着有人非法获取对网络服务器的访问权限，最多可以看到所有收到的付款，但是无法窃取钱，不能（简单地）区分出去的交易，在存在交易的情况下也不能看到其他网络服务器收到的付款。

# 安全性

为符合本标准，客户端必须至少能够导入扩展的公钥或私钥，才能将其直接后代作为钱包密钥访问。 说明书第二部分中提供的钱包结构（主/账户/链/子链）仅供参考，但建议作为最小结构，以便易于兼容 - 即使没有单独的帐户或内部和外部链条之间的区别。然而，实现可能会因特定需求而偏离它; 更复杂的应用程序可能需要更复杂的树结构。
安全

除了期望EC公钥自己加密之外：

* 给定公钥K，攻击者无法通过比解决EC离散对数问题（假定需要2^128个组操作）更有效地方式找到相应的私钥。

本标准的预期安全属性有：

* 给定一个子扩展私钥（ki，ci）和整数i，攻击者不能比HMAC-SHA512的2^256暴力更有效地方式找到父私钥kpar。

* 给定具有不同ij的（索引，扩展私钥）元组（ij，（kij，cij））的任何数目（2≤N≤2^32-1），确定它们是否从公开父扩展私钥派生（即，是否存在一个（kpar，cpar），使得对于（0..N-1）中的每个j，CKDpriv（（kpar，cpar），ij）=（kij，cij））不能比2^256复杂度的HMAC-SHA512更有效的完成。

请注意以下属性不存在：

* 给定父扩展公钥（Kpar，cpar）和子公钥（Ki），很难找到i。

* 给定一个父扩展公钥（Kpar，cpar）和一个非增强子私钥（ki），很难找到Kpar。

# 含义

私钥和公钥必须像往常一样保持安全。泄露私钥意味着可以花费比特币泄露公钥可能意味着失去隐私。

对于扩展密钥，必须更加小心，因为它们对应于整个（子）密钥树。

一个弱点可能不是很明显的，就是知道父扩展公钥加上从它分散的任何非增强私钥相当于知道父扩展私钥（因此知道从其分散的每个私钥和公钥）。这意味着扩展公钥必须比常规公钥更仔细地对待。 这也是增强密钥存在的原因，为什么它们被用于树中的帐户级别。这样一来，专用（或更低）私钥的泄漏就不会危害主账号或其他账户。

# 测试向量

## 测试向量1

发送 (hex): 000102030405060708090a0b0c0d0e0f

Chain m

ext pub: xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8    
ext prv: xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi  

Chain m/0H

ext pub: xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw  
ext prv: xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7  

Chain m/0H/1
ext pub: xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ  
ext prv: xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs  

Chain m/0H/1/2H

ext pub: xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5  
ext prv: xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM  

Chain m/0H/1/2H/2

ext pub: xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV  
ext prv: xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334  

Chain m/0H/1/2H/2/1000000000

ext pub: xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy  
ext prv: xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76  

## 测试向量2

发送 (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542

Chain m

ext pub: xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB  
ext prv: xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U  

Chain m/0

ext pub: xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH  
ext prv: xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt  

Chain m/0/2147483647H

ext pub: xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a  
ext prv: xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9  

Chain m/0/2147483647H/1

ext pub: xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon  
ext prv: xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef  

Chain m/0/2147483647H/1/2147483646H

ext pub: xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL  
ext prv: xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc  

Chain m/0/2147483647H/1/2147483646H/2

ext pub: xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt  
ext prv: xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j  

## 测试向量3

These vectors test for the retention of leading zeros. 在 [bitpay/bitcore-lib#47](https://github.com/bitpay/bitcore-lib/issues/47) 和 [iancoleman/bip39#58](https://github.com/iancoleman/bip39/issues/58) 查看更多信息。

Seed (hex): 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be

Chain m

ext pub: xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13  
ext prv: xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6  

Chain m/0H

ext pub: xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y  
ext prv: xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L  

# 实现

Two Python implementations exist:

* PyCoin [https://github.com/richardkiss/pycoin](https://github.com/richardkiss/pycoin) is a suite of utilities for dealing with Bitcoin that includes BIP0032 wallet features.  BIP32Utils [https://github.com/jmcorgan/bip32utils](https://github.com/jmcorgan/bip32utils) is a library and command line interface specifically focused on BIP0032 wallets and scripting.

* 2 Java implementations exist: [https://github.com/bitsofproof/supernode/blob/1.1/api/src/main/java/com/bitsofproof/supernode/api/ExtendedKey.java ](https://github.com/bitsofproof/supernode/blob/1.1/api/src/main/java/com/bitsofproof/supernode/api/ExtendedKey.java )and [https://github.com/bushidowallet/bushido-java-core/tree/master/src/main/java/com/bushidowallet/core/bitcoin/bip32](https://github.com/bushidowallet/bushido-java-core/tree/master/src/main/java/com/bushidowallet/core/bitcoin/bip32)

* A C++ implementation is available at [https://github.com/ciphrex/mSIGNA/blob/master/deps/CoinCore/src/hdkeys.h](https://github.com/ciphrex/mSIGNA/blob/master/deps/CoinCore/src/hdkeys.h)

* An Objective-C implementation is available at [https://github.com/oleganza/CoreBitcoin/blob/master/CoreBitcoin/BTCKeychain.h](https://github.com/oleganza/CoreBitcoin/blob/master/CoreBitcoin/BTCKeychain.h)

* A Ruby implementation is available at [https://github.com/GemHQ/money-tree](https://github.com/GemHQ/money-tree)

Two Go implementations exist:

* hdkeychain [https://github.com/conformal/btcutil/tree/master/hdkeychain](https://github.com/conformal/btcutil/tree/master/hdkeychain) provides an API for bitcoin hierarchical deterministic extended keys (BIP0032).  Go HD Wallet [https://github.com/WeMeetAgain/go-hdwallet](https://github.com/WeMeetAgain/go-hdwallet).

Two JavaScript implementations exist: available at [https://github.com/sarchar/brainwallet.github.com/tree/bip32](https://github.com/sarchar/brainwallet.github.com/tree/bip32) and [https://github.com/bitpay/bitcore](https://github.com/bitpay/bitcore)

* A PHP implementation is available at [https://github.com/Bit-Wasp/bitcoin-lib-php](https://github.com/Bit-Wasp/bitcoin-lib-php)

* A C# implementation is available at [https://github.com/NicolasDorier/NBitcoin](https://github.com/NicolasDorier/NBitcoin) (ExtKey, ExtPubKey)

* A Haskell implementation is available at [https://github.com/haskoin/haskoin](https://github.com/haskoin/haskoin) together with a CLI interface at [https://github.com/np/hx](https://github.com/np/hx)

# 致谢

- Gregory Maxwell提出了2型确定性钱包的原始想法，并对此进行了许多讨论。

- Alan Reiner在Armory中实施这一计划，并随后提出了一些建议。

- Eric Lombrozo审查和修改此BIP。

- Mike Caldwell为版本字节表示便于识别的Base58字符串作出贡献。























