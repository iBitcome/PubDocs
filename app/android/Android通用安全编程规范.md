# Android通用安全编程规范

随着移动互联网的发展，移动终端安全也越来越受到关注。移动应用程序现在变得更复杂，有许多第三方库和成千上万的功能，并且可以访问个人敏感数据和网络，这也导致了个人隐私数据泄露的不断增多。特别是Android系统的崛起，互联网上的各类Andriod软件数量迅速上升。因Android系统是开源的，导致各种android恶意软件迅猛增加，成为手机系统的最大受害者。与此同时，androi软件本身的漏洞也进一步危害到用户的隐私安全。本章节主要针对Android应用软件提出安全开发规范来指导Android app安全开发。

# 通用信息

## 基本信息

### Permission申请权限

AndroidManifest.xml文件的uses-permission标签选项所申请的权限必需APK所需要的。

### Permission权限等级设置

需要注意的是，在声明权限时需要一个android:protectionLevel 的属性，它代表“风险级别”。必须是以下4个值之一：normal、dangerous、signature、signatureOrSystem。

* normal表示权限是低风险的，不会对系统、用户或其他应用程序造成危害。
* dangerous表示权限是高风险的，系统将可能要求用户输入相关信息，才会授予此权限。
* signature告诉Android，只有当应用程序所用数字签名与声明此权限的应用程序所有数字签名相同时，才能将权限授给它。
* signatureOrSystem告诉Android，将权限授给具有相同数字签名的应用程序或Android包类，这一级别适用于非常特殊的情况，比如多个供应商需要通过系统影像共享功能时。

另外一个是android:permissionGroup 属性，表示一个权限组。可以将权限放在一个组中，但对于自定义权限，应该避免设置此属性。如果确实希望设置此属性，可以使用以下属性代替：android.permission-group.SYSTEM_TOOLS。

在2011年，香港理工大学的安全研究人员陆续报告了许多android软件中存在的Content Provider信息泄露漏洞，由于程序对Provider的权限设置不当，导致第三方软件可读取Content Provider提供的信息，其危害程度取决于Content Provider提供的信息内容，比如联系人、电话、短信等隐私信息就可能包含其中。默认情况下，Content Provider的权限为android:protectionLevel=”normal”， 最好的权限设置应为signature或者signatureOrSystem，进而避免被第三方恶意软件利用。

除protectionLevel权限问题外，<grant-uri-permission>权限若设为true，可被其它程序通过URL访问到content provider的内容，容易造成信息泄露。

###  allowBackup属性

Android API Level 8及其以上Android系统提供了为应用程序数据的备份和恢复功能，此功能的开关决定于该应用程序中AndroidManifest.xml文件中的allowBackup属性值，其属性值默认是True。当allowBackup标志为true时，用户即可通过adb backup和adb restore来进行对应用数据的备份和恢复，这可能会带来一定的安全风险。

Android属性allowBackup安全风险源于adb backup容许任何一个能够打开USB 调试开关的人从Android手机中复制应用数据到外设，一旦应用数据被备份之后，所有应用数据都可被用户读取；adb restore容许用户指定一个恢复的数据来源（即备份的应用数据）来恢复应用程序数据的创建。因此，当一个应用数据被备份之后，用户即可在其他Android手机或模拟器上安装同一个应用，以及通过恢复该备份的应用数据到该设备上，在该设备上打开该应用即可恢复到被备份的应用程序的状态。

尤其是通讯录应用，一旦应用程序支持备份和恢复功能，攻击者即可通过adb backup和adb restore进行恢复新安装的同一个应用来查看聊天记录等信息； 对于支付金融类应用，攻击者可通过此来进行恶意支付、盗取存款等；因此为了安全起见，开发者务必将allowBackup标志值设置为false来关闭应用程序的备份和恢复功能，以免造成信息泄露和财产损失。
AndroidManifest.xml文件，属性android:allowbackup必需设置为false。

## 危险敏感行为

敏感行为包括发送、拦截短信，读取、修改通讯录、通话记录，拨打电话，发送地理位置，使用摄像头，访问浏览器历史记录等。函数调用这些敏感行为，可能导致用户隐私数据泄露，钓鱼扣费等风险。
必需严格限制调用敏感函数。

# 动态调试

android:debuggable="true" 时我们可以在手机上调试Android程序，在进程中注入代码和导致敏感和个人隐私数据库泄露。

打开AndroidManifest.xml文件，属性 android:debuggable设置为false。

但是当我们没在AndroidManifest.xml中设置其debug属性时:使用Eclipse运行这种方式打包时其debug属性为true,使用Eclipse导出这种方式打包时其debug属性为false。

在使用ant打包时，其值就取决于ant的打包参数是release还是debug。因此在AndroidMainifest.xml中最好不设置 android:debuggable属性置，而是由打包方式来决定其值。

# 组件安全

在Android中存在多种组件，比如Activity、Service、Content Provider、Broadcast Receiver等等，这些组件可能因权限设置不当或者其他编程未遵守开发安全规范导致信息泄露或者钓鱼欺骗等攻击。

## APP四大组件安全设置

每个组件都可在 AndroidManifest.xml里通过属性exported被设置为私有或公有。私有或公有的默认设置取决于此组件是否被外部使用；例如某组件设置了intent-filter意味着该组件可以接收intent，可以被其他应用访问，则默认的exported属性为true(没有filter只能通过明确的类名来启动activity故相当于只有程序本身能启动)，反之为false（意味着此组件只能由自身的app(同userid或root也行)启动）。需要注意的是 ContentProvider默认为true，毕竟是共享数据的组件。

公有组件能被任何应用程序的任何组件所访问。这是非常有必要的，如MainActivity 通常是公有的，方便应用启动；然而大多数组件需要对其加以限制，下面我们针对不同组件来讨论。

### Activity安全

私有组件此时Activity只能被自身app启动。（同user id或者root也能启动）

情况一：私有 Activity 不能被其他应用启动相对安全。

创建 Activity时：

* 不指定 taskAffinity //task 管理 Activity。task 的名字取决于根 Activity的 affinity。默认设置中 Activity 使用包名做为 affinity。task 由 app 分配，所以一个应用的 Activity 在默认情况下属于相同 task。跨 task 启动 Activity 的 intent 有可能被其他 app 读取到。
* 不指定 lanchMode //默认standard，建议使用默认。创建新 task 时有可能被其他应用读取 intent的内容。
* 设置 exported 属性为false。
* 谨慎处理从 intent 中接收的数据，不管是否内部发送的 intent。
* 敏感信息只能在应用内部操作。

使用 Activity时：

* 开启Activity时不设置 FLAG_ACTIVITY_NEW_TASK 标签。FLAG_ACTIVITY_NEW_TASK 标签用于创建新 task（被启动的 Activity 并未在栈中）。
* 开启应用内部 Activity 使用显示启动的方式。
* 当 putExtra() 包含敏感信息目的应是 app 内的 Activity。
* 谨慎处理返回数据，即可数据来自相同应用。

情况二：公开暴露的 Activity 组件，可以被任意应用启动。

创建Activity：

* 设置 exported 属性为 true；
* 谨慎处理接收的 intent；
* 有返回数据时不应包含敏感信息。

使用Activity：

* 不应发送敏感信息；
* 当收到返回数据时谨慎处理More information about Secure Activity。

### Service安全

通常Service执行的操作比较敏感，如更新数据库，提供事件通知等，因此一定要确保访问 Service 的组件有一定权限(也就是给Service设置权限)。

在 AndroidManifest.xml 里给 Service 设置权限(可自定义)。一般设置exported属性为false(或没有intent-filter)；如果需要给别的app访问即此属性设置为true，最好做敏感操作的时候通过 checkCallingPermission()方法来提供权限检测。

不要轻易把Intent传递给公有的未知名的 Service；最好在所传递的Intent中提供完整类名，或者在ServiceConnection的onServiceConnected(ComponentName, Ibinder)里检验Service的包名。

### Content Provider安全

Content Provider为其他不同应用程序提供数据访问方式，需要更复杂的安全措施保护。
读写权限分开。一旦应用程序来访，Content Provider 需要对权限检测，只有拥有只读/只写权限才允许建立连接，否则抛出 SecurityException。
只读/只写一旦实施就适用于所有数据，如果播放器只要特定音乐数据，给播放器全部访问权限，岂不是权限很大，为了细分权限粒度，可以使用 Grant-uri-permission 机制来指定一个数据集。Content Provider 可通过属性 <grant-uri-permission> 为其内的 URI 设置临时访问权限。

### Broadcast Receiver安全

应用通常用它来监听广播消息。

广播发送方通常选择给每个发送Broadcast Intent授予Android权限；接收方不但需要符合Intent filter的接收条件，还要求Broadcast Receiver也必须具有特定权限(给发送方授予权限要一致)才能接收(双层过滤)。

## Webview组件安全

Webview是Android用于浏览网页的组件，其包含的接口函数addJavascriptInterface可以将Java类或方法导出以供JavaScript调用，实现网页JS与本地JAVA的交互。由于系统没有限制已注册JAVA类的方法调用，因此未注册的其它任何JAVA类也可以被反射机制调用，这样可能导致被篡改的URL中存在的恶意代码被执行，用户手机被安装木马程序，发送扣费短信，通讯录或者短信被窃取，甚至手机被远程控制。

* 打开AndroidManifest.xml文件，检查属性 android:targetSdkVersion是否设置到17及以上。
* 安卓4.2及以上版本（API >= 17），检查在注入类中为可调用的方法是否添加添加@JavascriptInterface注解，无注解的方法不能被调用，这种方式可以防范注入漏洞。安卓4.2及以下版本（ API =< 17），肯定不能再调用addJavascriptInterface方法了，关于这个问题，最核心的就是要知道JS事件这一个动作，JS与Java进行交互我们知道，有以下几种，比prompt,alert等，这样的动作都会对应到WebChromeClient类中相应的方法，对于prompt，它对应的方法是onJsPrompt方法，这个方法的声明如下：

```

public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result)

```

通过这个方法，JS能把信息（文本）传递到Java，而Java也能把信息（文本）传递到JS中，通知这个思路我们能不能找到解决方案呢？

经过一番尝试与分析，找到一种比较可行的方案，请看下面几个小点：

【1】让JS调用一个Javascript方法，这个方法中是调用prompt方法，通过prompt把JS中的信息传递过来， 这些信息应该是我们组合成的一段有意义的文本，可能包含：特定标识，方法名称，参数等。在onJsPrompt方法中，我们去解析传递过来的文本，得到方法名，参数等，再通过反射机制，调用指定的方法，从而调用到Java对象的方法。

【2】关于返回值，可以通过prompt返回回去，这样就可以把Java中方法的处理结果返回到Js中。

【3】我们需要动态生成一段声明Javascript方法的JS脚本，通过loadUrl来加载它，从而注册到html页面中，具体的代码如下：

```
    javascript:(function JsAddJavascriptInterface_(){  
        if (typeof(window.jsInterface)!='undefined') {      
            console.log('window.jsInterface_js_interface_name is exist!!');}   
        else {  
            window.jsInterface = {          
                onButtonClick:function(arg0) {   
                    return prompt('MyApp:'+JSON.stringify({obj:'jsInterface',func:'onButtonClick',args:[arg0]}));  
                },  
                  
                onImageClick:function(arg0,arg1,arg2) {   
                    prompt('MyApp:'+JSON.stringify({obj:'jsInterface',func:'onImageClick',args:[arg0,arg1,arg2]}));  
                },  
            };  
        }  
    }  
)()

```

安全建议：

1、使用removeJavascriptInterface("searchBoxJavaBridge_")移除searchBoxJavaBridge_对象。

2、不用addJavascriptInterface接口函数。使用shouldOverrideUrlLoading来限制安全域的方法并不太安全，别忘了中间人攻击。

3、调用removeJavascriptInterface("accessibility") 和removeJavascriptInterface("accessibilityTraversal")方法移除这两个默认接口。

## Intent消息
### 拒绝服务

Intent通常用于Activity、Service、Broadcast Receiver等组件之间进行信息传递，包括发送端和接收端，其负责对应用中一次操作的动作及数据进行描述。当intent中包含空数据、异常或者畸形数据时，如果Android应用程序没有对Intent.getXXXExtra()获取的异常或者畸形数据进行异常捕获，那么可导致接收该Intent的应用崩溃。拒绝服务攻击漏洞可能导致安全防护、监控类应用失效，也可能导致应用被大面积恶意攻击而崩溃，造成经济利益损失或者客户流失。

1、	对于四大组件，必需要有都有Intent!=null的条件判断。

2、	对于动态注册的BroadcastReceiver，如下例子存在getXXXExtra拒绝服务漏洞：

```

BroadcastReceiver receiver = new BroadcastReceiver() {
@Override
public void onReceive(Context arg0, Intent arg1) {
// TODO Auto-generated method stub
String string = arg1.getStringExtra("test");
}
};
public void registerReceiver(){
IntentFilter filter = new IntentFilter("com.test");
registerReceiver(receiver, filter);
}

```

解决方案：

1、对String string = arg1.getStringExtra("test");代码片段增加try catch异常保护。

2、当应用程序发送某个广播时系统会将发送的Intent与系统中所有注册BroadcastReceiver的IntentFilter进行匹配，若匹配成功则执行相应的onReceive函数。可以通过类似sendBroadcast(Intent, String)的接口在发送广播时指定接收者必须具备的permission。或通过Intent.setPackage设置广播仅对某个程序有效。

3、当应用程序注册了某个广播时，即便设置了IntentFilter还是会接收到来自其他应用程序的广播进行匹配判断。对于动态注册的广播可以通过类似registerReceiver(BroadcastReceiver, IntentFilter, String, android.os.Handler)的接口指定发送者必须具备的permission，对于静态注册的广播可以通过 android:exported="false"属性表示接收者对外部应用程序不可用，即不接受来自外部的广播。

4、上面两个问题其实都可以通过LocalBroadcastManager来解决。

### Intent组件隐式调用

**隐式Intent：** 通过Intent Filter来实现的，它一般用在没有明确指出目标组件名称的前提下，一般是用于在不同应用程序之间，必须加上 <</span>category android:name = "android.intent.category.DEFAULT" />

当使用隐式的Intent调用时，并未对intent消息接收端进行限制，因此可能存在该消息被未知的第三方应用劫持的风险。Intent消息被劫持，可能导致用户的敏感数据泄露，或者恶意程序执行等风险。

需要检查源代码是否采用隐式的Intent调用。例如下面的例子：

隐式的Intent调用：
```

Intent intent = new Intent(SecondActivity.this,“com.st.org.main”);

//启动Activity

startActivity(intent)

```

修改方案如下：

采用显式的Intent调用：
```

//显示方式声明Intent，直接启动SecondActivity

Intent it = new Intent(MainActivity.this,SecondActivity.class);

//启动Activity

startActivity(it);
```

### Intent Scheme URL攻击

在Android上的Intent-based攻击很普遍，这种攻击轻则导致应用程序崩溃，重则可能演变提权漏洞。当然，通过静态特征匹配，Intent-Based的恶意样本还是很容易被识别出来的。然而最近出现了一种基于Android Browser的攻击手段——Intent Scheme URLs攻击。这种攻击方式利用了浏览器保护措施的不足，通过浏览器作为桥梁间接实现Intend-Based攻击。相比于普通Intend-Based攻击，这种方式极具隐蔽性，而且由于恶意代码隐藏WebPage中，传统的特征匹配完全不起作用。除此之外，这种攻击还能直接访问跟浏览器自身的组件（无论是公开还是私有）和私有文件，比如cookie文件，进而导致用户机密信息的泄露。
找到Intent.parseUri(uri)代码段，查看是否有设置category为BROWSABLE。
解决方案：

通过以上漏洞的描述，总结得出一种相对比较安全的Intent Filter方法，代码如下：

```

// convert intent scheme URL to intent object
Intent intent = Intent.parseUri(uri);
// forbid launching activities without BROWSABLE category
intent.addCategory("android.intent.category.BROWSABLE");
// forbid explicit call  
intent.setComponent(null);  
// forbid intent with selector intent
intent.setSelector(null);
// start the activity by the intent
context.startActivityIfNeeded(intent, -1);

```

### Activity劫持与截屏保护

android为了提高用户的用户体验，对于不同的应用程序之间的切换，基本上是无缝。他们切换的只是一个activity，让切换的到前台显示，另一个应用则被覆盖到后台，不可见。Activity的概念相当于一个与用户交互的界面。如果在启动一个Activity时，给它加入一个标志位FLAG_ACTIVITY_NEW_TASK，就能使它置于栈顶并立马呈现给用户。

但是这样的设计却有一个缺陷。在Android系统当中，程序可以枚举当前运行的进程而不需要声明其他权限。恶意程序启动一个后台的服务，这个服务不断地扫描当前运行的进程，当发现目标进程启动时，就启动一个伪装的Activity。如果这个Activity是登录界面，那么就可以从中获取用户的账号密码。

屏幕劫持也是一个重要的安全风险。在用户一些重要的操作需要输入个人隐私数据和敏感信息的时候如果被恶意程序截屏，将会造成一定的安全风险，导致敏感和个人隐私数据库泄露。
针对Activity劫持和截屏，在移动应用开发阶段需要做如下保护：

目前，还没有什么专门针对Activity劫持的防护方法，因为，这种攻击是用户层面上的，目前还无法从代码层面上根除。但是，可以适当地在APP中给用户一些警示信息，提示用户其登陆界面以被覆盖，并给出覆盖正常Activity的类名。

在Activity的onCreate()方法的Layout初始化部分加入以下代码Window win = getWindow();win.addFlags(WindowManager.LayoutParams.FLAG_SECURE)防止截屏或者禁止截屏。

# 敏感数据

## 敏感数据存储

敏感信息明文保存一直是Andriod软件常容易出现的，这些敏感信息包括用户密码、住址、姓名等等内容，特别是密码问题。有些支持“记住密码”功能的软件常常将密码明文保存在软件目录下的某xml或者sqlite文件中，若手机中毒或者被其它恶意软件利用，直接读取xml或者sqlite文件中的明文密码然后远程发送给攻击者，这将会严重影响到用户帐号安全。

### 检查

示例代码：

```
package com.xiaod.sqlinj;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import android.database.sqlite.SQLiteOpenHelper;
import com.xiaod.User;
public class DatabaseHelper extends SQLiteOpenHelper {
public static final String TB_NAME="usertable";
public static final String ID="_id";
public static final String USERNAME="username";
public static final String PASSWORD="password";
public User user;
DatabaseHelper(Context context, String name, CursorFactory cursorFactory, int version) {
super(context, name, cursorFactory, version);
}
@Override
public void onCreate(SQLiteDatabase db) {
db.execSQL("CREATE TABLE IF NOT EXISTS "+
TB_NAME+" ("+ID+" INTEGER PRIMARY KEY,"+
USERNAME+" VARCHAR,"+PASSWORD+" VARCHAR )");
db.execSQL("INSERT INTO "+TB_NAME+"("+USERNAME+","+PASSWORD+") VALUES"+"(user.getName(),user.getPassword()");
}
```

### 解决方案

对敏感信息加密后再存储，示例代码如下：

```
package com.xiaod.sqlinj;
import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteDatabase.CursorFactory;
import android.database.sqlite.SQLiteOpenHelper;
import com.xiaod.User;
import com.util.AESUtil;
public class DatabaseHelper extends SQLiteOpenHelper {
public static final String TB_NAME="usertable";
public static final String ID="_id";
public static final String USERNAME="username";
public static final String PASSWORD="password";
public User user;
DatabaseHelper(Context context, String name, CursorFactory cursorFactory, int version) {
super(context, name, cursorFactory, version);
}
@Override
public void onCreate(SQLiteDatabase db) {
db.execSQL("CREATE TABLE IF NOT EXISTS "+
TB_NAME+" ("+ID+" INTEGER PRIMARY KEY,"+
USERNAME+" VARCHAR,"+PASSWORD+" VARCHAR )");
db.execSQL("INSERT INTO "+TB_NAME+"("+USERNAME+","+PASSWORD+") VALUES"+"( AESUtil.encrypt(user.getName()),AESUtil.encrypt (user.getPassword())");
}
```

## 敏感数据传输

在2012年2月UCWEB浏览器被爆存在明文密码网络传输漏洞，若开启“云端加速”功能，在登录一些SSL站点时，它会将用户发送的WEB请求会转发到UC的代理服务器上，并且未进行任何加密处理，可能导致用户密码泄露。最初UC不承认此问题，后来在微博上确认存在此漏洞。对于存在明文网络传输的软件，若结合中间人攻击就极有可能造成密码泄露，特别是在KFC、麦当劳等公共场所。

### SSL链路检查

检查源代码实现http的工具类，查看在请求URL是否采用了https。现在APK较多的使用了Apache基金会下面的HttpClient工具类来实现http和https请求。因此需要检查HttpClient工具类是实现了http还是https。具体代码视情况而定。

### SSL证书检查

解决证书不被系统承认的方法，就是跳过系统校验。要跳过系统校验，就不能再使用系统标准的SSL SocketFactory了，需要自定义一个。然后为了在这个自定义SSL SocketFactory里跳过校验，还需要自定义一个TrustManager，在其中忽略所有校验，即TrustAll。

示例代码：

```

package com.http;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.http.client.HttpClient;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
public class HttpClientUtil {
	@SuppressWarnings("deprecation")
	public HttpClient getHttpClients(HttpClient httpClient1) throws Exception
	{
		HttpClient httpClient = httpClient1;
		 X509TrustManager xtm = new X509TrustManager() {
		      public void checkClientTrusted(X509Certificate[] chain,
		          String authType) throws CertificateException {
		      }
		      public void checkServerTrusted(X509Certificate[] chain,
		          String authType) throws CertificateException {
		      }
		      public X509Certificate[] getAcceptedIssuers() {
		        return new X509Certificate[] {};
		      }
		    };
		      SSLContext ctx = SSLContext.getInstance("SSL");
		      
		      // 使用TrustManager来初始化该上下文，TrustManager只是被SSL的Socket所使用
		      ctx.init(null, new TrustManager[] { xtm }, null);
		      SSLSocketFactory sf = new SSLSocketFactory(
		          ctx,
		          SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		      Scheme sch = new Scheme("https", 443, sf);
		      httpClient.getConnectionManager().getSchemeRegistry().register(sch);
		return null;
	}
}

```

不过，虽然这个方案使用了HTTPS，客户端和服务器端的通信内容得到了加密，嗅探程序无法得到传输的内容，但是无法抵挡“中间人攻击”。例如，在内网配置一个DNS，把目标服务器域名解析到本地的一个地址，然后在这个地址上使用一个中间服务器作为代理，它使用一个假的证书与客户端通讯，然后再由这个代理服务器作为客户端连接到实际的服务器，用真的证书与服务器通讯。这样所有的通讯内容都会经过这个代理，而客户端不会感知，这是由于客户端不校验服务器公钥证书导致的。

因此需要在客户端验证服务器端证书的合法性，例如：

SSLSocketFactory.STRICT_HOSTNAME_VERIFIER或者是自己实现对证书检查：

首先需要实现一个X509TrustManager接口，这个接口是用来判断服务器提供的证书是否可以被客户端信任。这个类需要一个证书，我们可以通过浏览器的导出证书功能，将服务器上我们自己创建的证书导出在本地。在MyX509TrustManager的构造方法中，利用CertificateFactory生成一个Certificate实例。checkClientTrusted是用来检查客户端的证书的，这里我们只需要检测服务器端的证书就可以了，因此checkClientTrusted方法体就不添加代码了。checkServerTrusted是用来检查服务器端证书的合法性的，我们在这里对它进行一些处理。我这里用了一个非常简单的方法，就是比较服务器端发送来的证书和自己本地的证书是否一致。如果没有一样的证书，就直接抛出异常。

```
    package com.uestc.test.upload; 
    import java.io.BufferedInputStream;  
    import java.io.FileInputStream;  
    import java.io.IOException;  
    import java.security.cert.Certificate;  
    import java.security.cert.CertificateException;  
    import java.security.cert.CertificateFactory;  
    import java.security.cert.X509Certificate;  
    import javax.net.ssl.X509TrustManager;  
    public class MyX509TrustManager implements X509TrustManager {  
        private Certificate cert = null;  
        public MyX509TrustManager() {  
            try {  
                FileInputStream fis = new FileInputStream(  
                        "/Users/justyoung/Desktop/upload/Cloud3");  
                BufferedInputStream bis = new BufferedInputStream(fis);  
                CertificateFactory cf = CertificateFactory.getInstance("X.509");  
                while (bis.available() > 0) {  
                    cert = cf.generateCertificate(bis);  
    //              System.out.println(cert.toString());  
                }  
                bis.close();  
            } catch (CertificateException | IOException e) {  
                e.printStackTrace();  
            }  
        }  
        @Override  
        public void checkClientTrusted(X509Certificate[] chain, String authType)  
                throws CertificateException {  
        }  
        @Override  
        public void checkServerTrusted(X509Certificate[] chain, String authType)  
                throws CertificateException {  
            for (X509Certificate cert : chain) {  
                if (cert.toString().equals(this.cert.toString()))  
                    return;  
            }  
            throw new CertificateException("certificate is illegal");  
        }  
        @Override  
        public X509Certificate[] getAcceptedIssuers() {  
            return new X509Certificate[] { (X509Certificate) cert };  
        }  
    }  
    
```

然后，又实现了一个HostnameVerifier接口，这个类主要是在SSL握手时验证对方主机名称的，这样做的一个目的也是防止链接被重定向到其他的不安全的地址上去，并且若出现服务器证书上的Hostname和实际的URL不匹配时，也能做一些处理，否则会抛出这样的异常：
javax.net.ssl.SSLPeerUnverifiedException: Host name '192.168.2.177' does not match the certificate subject provided by the peer，因此实现HostnameVerifier接口，我们能做一些hostname确认的工作，提高安全性。

```
    package com.uestc.test;
    import javax.net.ssl.HostnameVerifier;
    import javax.net.ssl.SSLSession;  
    public class MyVerifyHostname implements HostnameVerifier {  
        @Override  
        public boolean verify(String arg0, SSLSession arg1) {  
     if(arg0.equals("192.168.2.177")||arg0.equals("cyber-space2015.imwork.net"))
                return true;  
            else  
                return false;  
        }  
} 

```

# 加密算法使用

## 秘钥硬编码

对于AES等加密算法，AES密钥不能硬编码。

## 秘钥生成采用随机数

代码使用加密技术对敏感信息资产进行加密。Android应用需采用SecureRandom生成随机数，而不是采用Random或者Math.random()，用于程序的逻辑功能或者加密算法。错误的使用方式可造成生成的随机数并非完全随机分布，且产生重复的"随机值"。当SecureRandom类生使用相同的种子生成随机数时，生成的随机数也相同，这样可导致使用的随机数或加密算法被破猜解。

## 正确的使用加密算法
* 对于数据不需要还原场景，例如登录密码存储，检查是否采用需要保存的数据加颜值再用SHA1或者SHA2等安全的哈希算法加密。
* 对于数据需要还原的厂家，检查是否采用AES等安全的可逆加密算法加密，同时加密模式是否采用CBC模式。
* 对于银行等业务，请求数据是否采用先摘要，后用RSA签名后传输。并且RSA秘钥长度检查是否在2048位以上。

# 安全审计

## 版本发布日志关闭

在APK开发工程中，为了方便开发调试往往都采用log输出的方式。但是如果在正式版本发布后，没有删除日志打印，将会导致个人隐私数据和敏感数据泄露的风险。因此，有必要检查APK日志是否关闭。
一般来讲，检查release版本是否采用Boolean变量或者是采用ProGuard。具体检查如下：

* 条件判断方式

打印日志的时候，可能我们不只需要错误的msg，还希望得到调用者的堆栈(比如打log的函数名是什么，类名是什么)。所以，本人编写了一个可以封装这些信息的build函数来封装一些具体信息，用户只需要传入msg即可。并且通过debug开关，在程序发布时候关闭无用的日志调用：

```

public static class LogMsgBuidler  
{  
    private static boolean DEBUG = true; /* 默认开启 */  
    public static void reverse()  
    {  
        DEBUG = !DEBUG; /* 反转DEBUG设置 */  
    }  
    public static String build(String msg)  
    {  
        if (!DEBUG)  
            return msg;  
        // 获取堆栈信息  
        StackTraceElement caller = new Throwable().fillInStackTrace().getStackTrace()[2];  
        return new StringBuilder().append(caller.getClassName())  
            .append(".").  
            append(caller.getMethodName())  
            .append("(): ")  
            .append(msg).toString();  
    }  
}

```

* 配置工具方式

通过proguard来删除各种日志输出代码。然后导出apk时，将会过滤掉日志代码。配置proguard，将类android.util.Log的方法给置为为无效代码。（proguard是一个代码优化的工具，也可以混淆代码）

## 日志打印敏感信息

日志打印个人数据和敏感信息，将会导致日志泄露个人隐私数据和敏感信息的风险。因此需要检查log打印是否存在打印个人数据或者敏感信息包括但不限于：password、key、email、phone Number、address、银行卡号等等。例如：

```

Log.i("TAG", password);

```

# 异常处理

JAVA语言本身提供了统一的异常处理机制。在进行异常处理的时候需注意以下几种原则：

## 不要忽略捕获的异常

不正确写法：

```

class Foo implements Runnable{
Public void run(){
try{
 Thread.sleep(1000);
} catch (InterruptedException e){  
  //此处InterruptedException被忽略
}
}
}

```

正确写法：

```

class Foo implements Runnable{
Public void run(){
try{ 
Thread.sleep(1000);
} catch (InterruptedException e){
     Thread.currentThread().interrupt();     //Resetinterrupted status
}
}
}

```

对于捕获的异常要进行相应的处理，不能忽略已捕获的异常。


## 不允许暴露异常的敏感信息

没有过滤敏感信息的异常堆栈往往会导致信息泄漏。

不正确的写法：
    
```

try{
FileInputStreamfis = newFileInputStream(System.getenv("APPDATA")+args[0]);
}catch (FileNotFoundException e){
//Log the exception
thrownewIOException("Unable to retrieve file",e);
}

```

正确的写法：

```

class ExceptionExample{
public static void main(String[]args){
File file=null;
try{
file = newFile(System.getenv("APPDATA")+args[0]).getCanonicalFile();
if(!file.getPath().startsWith("c:\\homepath")){
log.error("Invalidfile");
return;
}
}catch (IOException x){
log.error("Invalidfile");
return;
}
try{
FileInputStreamfis = newFileInputStream(file);
}catch(FileNotFoundException x){
log.error("Invalidfile");
return;
}
}
}

```

不正确的写法：

```

boolean isCapitalized(String s){
if(s == null){
thrownewRuntimeException("NullString");
}
}
private void doSomething()throwsException{
//...
}

```

正确的写法：

```

boolean isCapitalized(String s){
if(s == null){
thrownewNullPointerException();
}
}
Private void doSomething()throwsIOException{
//...
}

```

## 不允许抛出RuntimeException,Exception,Throwable

不正确的写法：
```

boolean isName(String s){
try{
String names[]=s.split("");
if(names.length!=2){
return false;
}
return (isCapitalized(names[0])&&isCapitalized(names[1]));
}catch(NullPointerException e){
return false;
}
}

```

正确的写法：

```

boolean isName(Strings) {     /*throwsNullPointerException*/
String names[]=s.split("");
if(names.length!=2){
return false;
}
return (isCapitalized(names[0])&&isCapitalized(names[1]));
}

```

## 不要捕获NullPointerException或其他父类异常










