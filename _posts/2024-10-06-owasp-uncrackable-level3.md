---
title: Uncrackable - Level 3 | OWASP
date: 2024-10-06 20:54:00 +200
categories: [owasp, ctf, mobile, pentesting, uncrackable]
tags: [owasp, ctf, mobile, pentesting, uncrackable]
---

# OWASP Uncrackable | Level 3

## Introduction

After a long time, I'm here again with a next challenge from owasp for Android `Uncrackable Level 3`. As usual, I’ll begin with the starting point, which is `sg.vantagepoint.uncrackable3.MainActivity`.

Without furthure ado, I started analyzing the `MainActivity` what's new this time. In this level we need to put little more effort. If you check the code below from `MainActivity`, you can find this time we have `anti-frida` and `integrity` checks.

```java
public class MainActivity extends AppCompatActivity {
    private static final String TAG = "UnCrackable3";
    static int tampered = 0;
    private static final String xorkey = "pizzapizzapizzapizzapizz";
    private CodeCheck check;
    Map<String, Long> crc;

    private native long baz();

    private native void init(byte[] bArr);

    /* JADX INFO: Access modifiers changed from: private */
    public void showDialog(String str) {
        AlertDialog create = new AlertDialog.Builder(this).create();
        create.setTitle(str);
        create.setMessage("This is unacceptable. The app is now going to exit.");
        create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable3.MainActivity.1
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialogInterface, int i) {
                System.exit(0);
            }
        });
        create.setCancelable(false);
        create.show();
    }

    private void verifyLibs() {
        this.crc = new HashMap();
        this.crc.put("armeabi-v7a", Long.valueOf(Long.parseLong(getResources().getString(owasp.mstg.uncrackable3.R.string.armeabi_v7a))));
        this.crc.put("arm64-v8a", Long.valueOf(Long.parseLong(getResources().getString(owasp.mstg.uncrackable3.R.string.arm64_v8a))));
        this.crc.put("x86", Long.valueOf(Long.parseLong(getResources().getString(owasp.mstg.uncrackable3.R.string.x86))));
        this.crc.put("x86_64", Long.valueOf(Long.parseLong(getResources().getString(owasp.mstg.uncrackable3.R.string.x86_64))));
        try {
            ZipFile zipFile = new ZipFile(getPackageCodePath());
            for (Map.Entry<String, Long> entry : this.crc.entrySet()) {
                String str = "lib/" + entry.getKey() + "/libfoo.so";
                ZipEntry entry2 = zipFile.getEntry(str);
                Log.v(TAG, "CRC[" + str + "] = " + entry2.getCrc());
                if (entry2.getCrc() != entry.getValue().longValue()) {
                    tampered = 31337;
                    Log.v(TAG, str + ": Invalid checksum = " + entry2.getCrc() + ", supposed to be " + entry.getValue());
                }
            }
            ZipEntry entry3 = zipFile.getEntry("classes.dex");
            Log.v(TAG, "CRC[classes.dex] = " + entry3.getCrc());
            if (entry3.getCrc() != baz()) {
                tampered = 31337;
                Log.v(TAG, "classes.dex: crc = " + entry3.getCrc() + ", supposed to be " + baz());
            }
        } catch (IOException unused) {
            Log.v(TAG, "Exception");
            System.exit(0);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* JADX WARN: Type inference failed for: r0v2, types: [sg.vantagepoint.uncrackable3.MainActivity$2] */
    @Override // android.support.v7.app.AppCompatActivity, android.support.v4.app.FragmentActivity, android.support.v4.app.SupportActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        verifyLibs();
        init(xorkey.getBytes());
        new AsyncTask<Void, String, String>() { // from class: sg.vantagepoint.uncrackable3.MainActivity.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.os.AsyncTask
            public String doInBackground(Void... voidArr) {
                while (!Debug.isDebuggerConnected()) {
                    SystemClock.sleep(100L);
                }
                return null;
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // android.os.AsyncTask
            public void onPostExecute(String str) {
                MainActivity.this.showDialog("Debugger detected!");
                System.exit(0);
            }
        }.execute(null, null, null);
        if (RootDetection.checkRoot1() || RootDetection.checkRoot2() || RootDetection.checkRoot3() || IntegrityCheck.isDebuggable(getApplicationContext()) || tampered != 0) {
            showDialog("Rooting or tampering detected.");
        }
        this.check = new CodeCheck();
        super.onCreate(bundle);
        setContentView(owasp.mstg.uncrackable3.R.layout.activity_main);
    }

    public void verify(View view) {
        String obj = ((EditText) findViewById(owasp.mstg.uncrackable3.R.id.edit_text)).getText().toString();
        AlertDialog create = new AlertDialog.Builder(this).create();
        if (this.check.check_code(obj)) {
            create.setTitle("Success!");
            create.setMessage("This is the correct secret.");
        } else {
            create.setTitle("Nope...");
            create.setMessage("That's not it. Try again.");
        }
        create.setButton(-3, "OK", new DialogInterface.OnClickListener() { // from class: sg.vantagepoint.uncrackable3.MainActivity.3
            @Override // android.content.DialogInterface.OnClickListener
            public void onClick(DialogInterface dialogInterface, int i) {
                dialogInterface.dismiss();
            }
        });
        create.show();
    }

    static {
        System.loadLibrary("foo");
    }
}
```

>few more points to note.
{: .prompt-info }

* Something interesting here is a hard coded `xorkey` with length `24` which we might use later.

```java
private static final String xorkey = "pizzapizzapizzapizzapizz";
```

* We have a lib to load and the name is `libfoo.so`

```java
System.loadLibrary("foo");
```

* two native functions

```java
private native long baz();
private native void init(byte[] bArr);
```

## Setting up the frida hook script

To start, we need to write a Frida hook script to run the app and input a 24-character long string.

```bash
frida -U -f owasp.mstg.uncrackable3 -l .\UnCrackable-Level3\level3.js
```

>I used anti frida bypass code below from codeshare to save sometime
{: .prompt-tip }

```js
Java.perform(function() {
    var hook = Java.use("java.lang.System");
    hook.exit.implementation = function() {
        console.log("Root Check Bypassed!!! 😎");
    };
});

Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {

    onEnter: function(args) {

        this.haystack = args[0];
        this.needle = args[1];
        this.frida = Boolean(0);

        var haystack = Memory.readUtf8String(this.haystack);
        var needle = Memory.readUtf8String(this.needle);

        if (haystack.indexOf("frida") !== -1 || haystack.indexOf("xposed") !== -1) {
            this.frida = Boolean(1);
        }
    },

    onLeave: function(retval) {

        if (this.frida) {
            retval.replace(0);
        }
        return retval;
    }
});
```

![First Check](/assets/images/uncrackable_level3/owasp_level3_first_try.png)

With the basic bypass script ready, we can proceed to the main mission.

## Analyzing the Code

If you check the code above, we have a line where xorkey is getting used so I started with it for the next step.

```java
init(xorkey.getBytes());
```

Since the `init` function is defined in the native library, we need to load the native library in `Ghidra` to analyze the `init` function.

## Understanding the Native Code

![String Comparison](/assets/images/uncrackable_level3/owasp_level3_string_comparison.png)

The `strncpy` function is used as follows:
>char * strncpy ( char * destination, const char * source, size_t num );
{: .prompt-tip }

if you know about the `strncpy` it's clear that the source char pointer is `DAT_00115038` which is our point of interest.
When I check where else does `DAT_00115038` is getting used and I found that it's another function from nativ lib which is
`CodeCheck_bar`. Don't forget to check if size of the comparison, which is `0x18` i.e. 24 in decimal (do you still remember what we had earlier?).

![Secret Function In Bar](/assets/images/uncrackable_level3/owasp_level3_secret_function_in_bar.png)

The source char pointer is `DAT_00115038`, which is our point of interest. This pointer is also used in another function from the native library, `CodeCheck_bar`. Note that the size of the comparison is `0x18`, which is `24` in decimal (matching our XOR key length).

The local variable `local_68` is used in an if condition and is first populated inside the function `FUN_001010e0`. This function contains 1000 lines of code, making it impractical to check manually. However, the function parameter shows that the variable passed is a pointer, meaning something has returned from this function will be stored at that memory address. Since this function is not exported, we need its address to hook it. `Ghidra` shows the function’s address as `(0x10e0)`.

![Secret Function Location](/assets/images/uncrackable_level3/owasp_level3_secret_function_location.png)

## Key Points to Remember

>Before continuing with the hook script, keep these points in mind:
{: .prompt-info }
* We need to get the secret used with the XOR key.
* We need to XOR that key to find the actual result.

## Writing the Script

With these points in mind, let’s write the script. Ensure the native library is loaded before Frida starts hooking it (a lesson learned the hard way).

```js
var moduleName = 'libfoo.so';

setTimeout(function() {
    var baseAddress = Module.findBaseAddress(moduleName);
    var xorKey = "pizzapizzapizzapizzapizz";

    if (baseAddress) {
        var targetAddress = baseAddress.add(0x10e0);

        Interceptor.attach(targetAddress, {
            onEnter: function(args) {
                this.keyMemory = args[0];
            },
            onLeave: function(retval) {
                var length = 24;
                console.log('Function returned with value:', retval, this.keyMemory);
                var buffer = Memory.readByteArray(this.keyMemory, length);
                var key = new Uint8Array(buffer);

                var secret = "";

                for(var i=0; i < length; i++){
                    secret += key[i].toString() + "";
                }

                console.log("secret: ", secret);
                var result = [];

                for(var i=0; i < length; i++){
                    result[i] = String.fromCharCode(key[i] ^ xorKey.charCodeAt(i));
                }

                console.log("result ->", result.join(''));
            }
        });
        console.log('Hook attached at', targetAddress);
    }
}, 2000);
```

## Conclusion

Let’s run the script and complete this challenge!

```bash
(base) oreo@oreo:~/Documents/ctf/owasp-android/uncrackable_level3$ frida -l level3.js -f owasp.mstg.uncrackable3 -U
     ____
    / _  |   Frida 16.3.3 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to LE2101 (id=4a298ca9)
Spawned `owasp.mstg.uncrackable3`. Resuming main thread!                
[LE2101::owasp.mstg.uncrackable3 ]-> Hook attached at 0x7a999df0e0
Function returned with value: 0x7a263a4720 0x7fef0dea38
secret:  298171915237321130325902919218149002381920
result -> making owasp great again
```

![Result](/assets/images/uncrackable_level3/owasp_level3_output.gif)

Thanks for following along! Cheers 🍺
