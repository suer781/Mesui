import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Windows 编码墙之四：test worker 的 @argfile 由 java.exe 启动器在 JVM 启动前按
// ANSI(GBK) 解码，classpath 中的中文路径会变乱码 → 所有测试类 CNFE（jar 缓存路径
// 全 ASCII 所以不炸）。把构建目录迁到纯 ASCII 路径，让 classpath 不含任何中文。
// 仅 Windows 生效：该变通针对 GBK 编码墙，Linux CI 项目路径纯 ASCII 无此问题；
// 且 "C:/..." 在 Linux 上是相对路径，会把产物挪进项目树内的畸形目录，
// 偏离默认 outputs 路径（CI 的 artifact 上传会找不到 APK）。
if (System.getProperty("os.name").lowercase().contains("windows")) {
    layout.buildDirectory.set(File(System.getProperty("user.home"), "dc-build/app"))
}

android {
    namespace = "chat.dc.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "chat.dc.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
    // UniFFI 生成物：CI 在 assembleDebug 前由 uniffi-bindgen 生成到
    // src/main/uniffi（不入库），Kotlin 编译把它与 java 目录一并纳入。
    // 本地无该目录时 gradle 不报错，只是缺绑定源。
    sourceSets {
        getByName("main") {
            java.srcDir("src/main/uniffi")
        }
    }
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            all { test ->
                // Robolectric 的 android-all 运行时镜像走国内源
                test.systemProperty("robolectric.dependency.repo.url", "https://maven.aliyun.com/repository/public")
                test.systemProperty("robolectric.dependency.repo.id", "aliyun")
                // 项目路径含中文：worker JVM 默认按 GBK 解码路径导致测试类 CNFE
                //（本项目第三次撞 Windows 编码墙：GNU ld / aapt2 之后是 test worker）
                test.jvmArgs("-Dfile.encoding=UTF-8", "-Dsun.jnu.encoding=UTF-8")
            }
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.navigation:navigation-compose:2.8.5")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    // 二维码加好友（SP-3 v2）：core 生成、embedded 扫码（自带 CaptureActivity）
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    // Rust 核心经 UniFFI 的 Kotlin 绑定：libdc_core.so（三 ABI）由 CI 的
    // cargo-ndk 步骤放入 jniLibs；生成代码用 JNA 做 native 桥，
    // @aar 强制取 Maven Central 上与 jar 并行发布的 aar 打包（pom 的
    // packaging 是 jar，不带后缀会解析错）。
    implementation("net.java.dev.jna:jna:5.13.0@aar")

    testImplementation(composeBom)
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.compose.ui:ui-test-junit4")
    testImplementation("androidx.compose.ui:ui-test-manifest")
}
