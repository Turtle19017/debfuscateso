# Embedded DEX overlay path: `runOnUiThread` + `ViewAdder`

The natural post-Dex CFF path can now be followed past the persistent `GLES3JNIView` global reference and cross-checked against the extracted embedded DEX.

The key result is that the Java-side continuation is a normal UI-thread overlay insertion path. It constructs a `ViewAdder` `Runnable` and calls `Activity.runOnUiThread(...)`; `ViewAdder.run()` then calls `Window.addContentView(...)` with full-screen layout parameters.

## Native continuation after the persistent view GlobalRef

The prior stage constructs `com.ysmteam.imgui.GLES3JNIView`, replaces the persistent JNI GlobalRef at `0x5376E0`, and then reaches:

```text
0x271948 -> 0x272BB8 -> JNIEnv +0xF8 -> GetObjectClass
```

The object passed to this call is the captured Android `Activity`, not the newly created view. The following lazy-string pairs decode exactly to:

```text
0x2719B4 -> 0x272BC4   getter
0x271A18 -> 0x272C50   decoder
    "runOnUiThread"

0x271A84 -> 0x272CB0   getter
0x271AE8 -> 0x272D94   decoder
    "(Ljava/lang/Runnable;)V"
```

The call at:

```text
0x271B6C -> 0x2728C4 -> JNIEnv +0x108 -> GetMethodID
```

therefore obtains:

```java
Activity.runOnUiThread(java.lang.Runnable)
```

The next encoded class name is:

```text
0x271BD8 -> 0x272DCC   getter
0x271C34 -> 0x272EB0   decoder
    "com.ysmteam.imgui.ViewAdder"
```

and:

```text
0x271CA4 -> 0x35643C
```

uses the already captured application `ClassLoader` to execute `loadClass(...)`.

The post-load CFF dispatch resolves to:

```text
ViewAdder class != NULL -> 0x271D30
ViewAdder class == NULL -> 0x2722B0
```

## `ViewAdder` constructor lookup

The next two encoded strings are:

```text
0x271DB0 -> 0x272F20
0x271E1C -> 0x272F90
    "<init>"

0x271E88 -> 0x272FF0
0x271EF4 -> 0x2730D4
    "(Landroid/app/Activity;Landroid/view/View;)V"
```

The call at:

```text
0x271F7C -> 0x2728C4 -> GetMethodID
```

therefore resolves the exact constructor:

```java
ViewAdder(Activity activity, View view)
```

Its result dispatch is:

```text
constructor methodID != NULL -> state 18 -> 0x271FF4
constructor methodID == NULL -> state 20 -> 0x272210
```

The block beginning at `0x271FF4` passes the following argument shape to the next varargs JNI call:

```text
JNIEnv *
ViewAdder class
<init> methodID
Activity object
GLES3JNIView object
```

which is the `NewObjectV` construction of the `ViewAdder` instance. The known local `NewObjectV` wrapper is at `0x272B04` and uses JNIEnv slot `+0xE8`.

The result dispatch is:

```text
new ViewAdder != NULL -> state 14 -> 0x272104
new ViewAdder == NULL -> state 24 -> 0x272210
```

The success block at `0x272104` then has the argument shape:

```text
JNIEnv *
Activity object
runOnUiThread methodID
ViewAdder object
```

and calls the local `CallVoidMethodV` wrapper at `0x273168`, whose terminal JNIEnv-table load is:

```asm
ldr x8,[x0]
ldr x8,[x8,#0x1F0]     // CallVoidMethodV
blr x8
```

Semantically the native path is therefore:

```java
Class<?> activityClass = activity.getClass();
Method runOnUiThread = Activity.runOnUiThread(Runnable);

Class<?> adderClass = appClassLoader.loadClass(
    "com.ysmteam.imgui.ViewAdder"
);

Constructor<?> ctor = adderClass.getConstructor(
    Activity.class,
    View.class
);

Runnable adder = new ViewAdder(activity, gles3View);
activity.runOnUiThread(adder);
```

The code is implemented with JNI method IDs rather than Java reflection objects, but the semantics above match the argument flow exactly.

## Extracted DEX identity

The embedded DEX extracted from the inner image is:

```text
magic       dex\n037\0
size        3668 bytes
SHA-256     fdef253bbfbc40cff2de3f5e53fd3412f41a4912018978cd2f8a92f9e441a66b
method_ids  40
class_defs  3
```

The three classes are exactly:

```text
Lcom/ysmteam/imgui/GLES3JNIView;
Lcom/ysmteam/imgui/MainActivity;
Lcom/ysmteam/imgui/ViewAdder;
```

This independently confirms every class and method descriptor recovered from the native CFF path.

## Exact `ViewAdder` DEX body

`ViewAdder` has exactly two instance fields:

```java
Activity activity;
View view;
```

Its constructor code item is at DEX offset `0x67C` and is semantically:

```java
ViewAdder(Activity activity, View view) {
    super();
    this.activity = activity;
    this.view = view;
}
```

Its `run()` code item is at DEX offset `0x69C`. The exact referenced methods/types are:

```text
android/view/ViewGroup$LayoutParams.<init>(II)V
android/app/Activity.getWindow()Landroid/view/Window;
android/view/Window.addContentView(
    Landroid/view/View;
    Landroid/view/ViewGroup$LayoutParams;
)V
java/lang/Exception.printStackTrace()V
```

The single encoded catch handler covers instruction units `0..16` and catches exactly:

```text
Ljava/lang/Exception;
```

The Java-equivalent body is:

```java
public void run() {
    try {
        ViewGroup.LayoutParams params =
            new ViewGroup.LayoutParams(-1, -1);

        activity.getWindow().addContentView(view, params);
    } catch (Exception e) {
        e.printStackTrace();
    }
}
```

So the inserted view is full-screen (`MATCH_PARENT`, `MATCH_PARENT`).

## Exact `GLES3JNIView` Java setup

The DEX constructor code item at `0x52C` reduces to:

```java
GLES3JNIView(Context context) {
    super(context);
    setEGLConfigChooser(8, 8, 8, 8, 16, 0);
    getHolder().setFormat(-3);
    setZOrderOnTop(true);
    setEGLContextClientVersion(3);
    setRenderer(this);
    setRenderMode(1);
}
```

Its Java renderer/lifecycle callbacks are very small wrappers around native methods:

```text
onSurfaceCreated(...)      -> init()
onSurfaceChanged(...,w,h)  -> resize(w,h)
onDrawFrame(...)           -> step()
onDetachedFromWindow()     -> super + imgui_Shutdown()
onTouchEvent(event)        -> onTouch(
                                  event.getActionMasked(),
                                  event.getX(),
                                  event.getY())
```

This is the complete Java-to-native bridge used by the ImGui/OpenGL overlay view.

## `MainActivity` in the embedded DEX

The third class is a minimal standalone activity wrapper:

```java
static {
    System.loadLibrary("ysmteam");
}

protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    glView = new GLES3JNIView(this);
    setContentView(glView);
}

protected void onDestroy() {
    super.onDestroy();
    glView = null;
}
```

The production native path does not need to launch this activity. Instead it dynamically loads the same DEX classes into the host application's class loader and inserts `GLES3JNIView` into the existing Free Fire Max activity through `runOnUiThread` + `Window.addContentView`.

## Architectural consequence

The Java-side initialization chain is now closed end-to-end:

```text
DexLoader 0x355944
  -> loadClass("com.ysmteam.imgui.GLES3JNIView")
  -> new GLES3JNIView(activity)
  -> persistent GlobalRef @ 0x5376E0
  -> Activity.getClass()
  -> GetMethodID("runOnUiThread", "(Ljava/lang/Runnable;)V")
  -> loadClass("com.ysmteam.imgui.ViewAdder")
  -> GetMethodID("<init>", "(Activity,View)V")
  -> new ViewAdder(activity, gles3View)
  -> activity.runOnUiThread(viewAdder)
  -> Window.addContentView(gles3View, MATCH_PARENT x MATCH_PARENT)
```

This explains why the immediate post-Dex CFF path does not enter the IL2CPP resolver at `0x3016AC`: its first job is to install the Java/OpenGL overlay into the host activity. The exact incoming edge to `0x3016AC` remains a separate later target.
