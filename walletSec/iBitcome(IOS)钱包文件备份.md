# iBitcome(IOS)钱包文件备份


## 前言

>关于助记词到私钥生成的分析请参考[iBitcome(IOS)钱包公私钥对创建分析](./iBitcome\(IOS\)钱包公私钥对创建分析.md)

>关于keystore对象生成的分析请参考[iBitcome(IOS)钱包keystore文件创建分析](./iBitcome\(IOS\)钱包keystore文件创建分析.md)


## 备份

iBitcome钱包的备份分为助记词备份、keystore文件备份、私钥备份。


### 助记词备份

在[iBitcome(IOS)钱包keystore文件创建分析](./iBitcome\(IOS\)钱包keystore文件创建分析.md)里面已经提到了创建keystore文件的时候，把助记词用授权口令做密钥进行了aes加密后存储。那么备份是怎么做的呢，从代码来看有两个controller里面都有提到备份助记词，其实流程都差不多我们就分析其中一个就好了。

>**说明：这些controller都是继承了BaseViewController这个类，而BaseViewController则是继承了Objective-C的原生类UIViewController。**

先从`Beecoin.controllers.create_flow.BackUpWarningViewController.swift`跟踪。在这个controller里面有一个backupButton，一看就知道是备份按钮， 此按钮的配置代码如下：

```
private lazy var backupButton = UIButton().then { (btn) in
        btn.backgroundColor = R.clr.bitCome.mainAbleBtn()
        btn.setTitle(R.string.infoPlist.backupWarningBtnBu.localized(), for: UIControlState.normal)
        btn.rstDrawCorner(withRadiuce: 5)
        btn.setTitleColor(UIColor.white, for: UIControlState.normal)
        btn.titleLabel?.font = UIFont.bold16()
        btn.addTarget(self, action: #selector(onBackupButtonClicked(_:)), for: UIControlEvents.touchUpInside)
    }
```
此函数最后一行代码，一看就是添加一个时间监听，监听函数实现onBackupButtonClicked，那么查看此函数就好了。此函数代码较长，那么我们看重点就好了。

`alert.rightEvent`一看就是确认右键的实现，主要有几个重点：

`let showVC = ShowMnemonicViewController()`，实例化一个对象，然后

`showVC.mnemonic = try self.wallet!.encryptMnemonic!.decryptBase64ToString(cipher: AES(key: Padding.zeroPadding.add(to: password.bytes, blockSize: AES.blockSize), blockMode: BlockMode.ECB))`将wallet里面对加密对助记词用输入授权口令进行AES解密得到原始对助记词，然后赋值给showVC的mnemonic属性。

`showVC.wallet = self.wallet`，将钱包对象wallet赋值给showVC的wallet属性。

`self.navigationController?.pushViewController(showVC, animated: true)`，这里应该就是需要跳转到下个页面即是ShowMnemonicViewController。

那么看看ShowMnemonicViewController里面的实现呢。

同理，ShowMnemonicViewController里面定义了一个确认按钮，代码如下：
```
private lazy var confirmButton = UIButton().then { (btn) in
        btn.backgroundColor = R.clr.bitCome.mainAbleBtn()
        btn.setTitle(R.string.infoPlist.backupMnemonicShowBtn.localized(), for: UIControlState.normal)
        btn.rstDrawCorner(withRadiuce: 5)
        btn.setTitleColor(UIColor.white, for: UIControlState.normal)
        btn.titleLabel?.font = UIFont.bold16()
        btn.addTarget(self, action: #selector(onConfirmButtonClicked(_:)), for: UIControlEvents.touchUpInside)
    }
```
从上面代码可以看到，同样需要跟踪的是此按钮的监听事件函数onConfirmButtonClicked，此函数的代码如下：

```
@objc fileprivate func onConfirmButtonClicked(_ sender: UIButton) -> Void {
        SensorsAnalyticsSDK.sharedInstance()?.track(SensorsKeys.Event.backUpConfirm1.rawValue)
        let confirmVC = ConfirmMnemonicViewController()
        confirmVC.mnemonic = mnemonic
        confirmVC.wallet = wallet
        confirmVC.popIndex = popIndex
        navigationController?.pushViewController(confirmVC, animated: true)
    }
```
代码很简单，实例化一个ConfirmMnemonicViewController的对象confirmVC，并且把助记词mnemonic和钱包对象wallet等赋值到comfirmVC到属性，然后跳转到confirmVC。

ConfirmMnemonicViewController同样也定义了一个确认按钮，代码如下：

```
private lazy var confirmButton = UIButton().then { (btn) in
        btn.nextStepButton(title: R.string.infoPlist.backupMnemonicConfirmBtnConfirm.localized())
        btn.addTarget(self, action: #selector(onConfirmButtonClicked(_:)), for: UIControlEvents.touchUpInside)
    }
```

此按钮的监听事件函数onConfirmButtonClicked，此函数代码较长，贴一下关键代码：

```
if mneList.finalMnemonicString == mnemonic
```
这里有个逻辑判断，就是用户输入的助记词和前面的controller传过来的解密后的助记词要相等，相等说明了用户抄写过助记词mnemonic，那么这里的右键事件代码：

```
alert.rightEvent = {
                alert.isHidden = true
                alert.disappearAnimation()
                AppCore.shared().getRtd().hasDeleteMnemonicflag = true
                if self.wallet != nil {
                    self.wallet!.encryptMnemonic = nil
                    DB.shareInstance().updateWallet(self.wallet!)
                }
                if self.popIndex == -1 {
                    self.navigationController?.tabBarController?.selectedIndex = 0
                    self.navigationController?.popToRootViewController(animated: true)
                }
                else {
                    self.navigationController?.popToViewController((self.navigationController?.viewControllers[2])!, animated: true)
                }
            }
```
从上面代码可以看到，首先是判断钱包对象wallet是否为空`self.wallet!.encryptMnemonic = nil`，不为空那么`self.wallet!.encryptMnemonic = nil`，把钱包对象wallet的属性encryptMnemonic从新赋值为空，然后`DB.shareInstance().updateWallet(self.wallet!)`，把钱包对象更新到db文件持久化。updateWallet函数位于`BeeCoin.models.db.DB.swift`，定义如下：

```
func updateWallet(_ wallet: Wallet) -> Void {
        try? database?.update(table: walletTable,
                             on: Wallet.Properties.all,
                             with: wallet,
                             where: Wallet.Properties.identifier == wallet.identifier!)
    }
```
代码很简单，调用WCDB这个开源库进行数据库db文件的更新。

>从备份助记词mnemonic可以看到，在用户备份助记词以后，钱包本身不会再保存助记词，因此需要用户妥善保存。

### keystore文件备份


### 私钥备份










    


















