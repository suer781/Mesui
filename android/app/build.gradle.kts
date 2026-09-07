import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Windows 编码墙之四：test worker 的 @argfile 由 java.exe 启动器在 JVM 启动前按
// ANSI(GBK) 解码，classpath 中的中文路径会变乱码 → 所有测试类 CNFE（jar 缓存路径
// 全 ASCII 所以不炸）。把构建目录迁到纯 ASCII 路径，让 classpath 不含任何中文。
layout.buildDirectory.set(File("C:/Users/13682/dc-build/app"))

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

    // TODO: Rust 核心经 UniFFI 生成的 AAR/JNI 桥（阶段 1 集成）
    // implementation(files("libs/dc-core.aar")) 或使用 cargo-ndk + jniLibs

    testImplementation(composeBom)
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
    testImplementation("androidx.test:core:1.6.1")
    testImplementation("androidx.compose.ui:ui-test-junit4")
    testImplementation("androidx.compose.ui:ui-test-manifest")
}
