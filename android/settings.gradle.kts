// 仓库顺序按网络环境切换（GitHub Actions 会设置 CI=true）：
// - CI（海外网络）：google()/mavenCentral() 直连最快最稳；国内镜像在海外
//   runner 上不稳定（实测 aliyun 返回 502，导致 compileDebugKotlin 解析失败）。
// - 本机（国内网络，dl.google.com 被墙）：阿里云镜像优先，原源仅作后备。
// 注意：pluginManagement 块由 Gradle 独立编译执行，引用不到脚本顶层变量，
// 所以 onCi 需在各块内部声明。
pluginManagement {
    val onCi = System.getenv("CI") == "true"
    repositories {
        if (onCi) {
            google()
            mavenCentral()
            gradlePluginPortal()
        } else {
            // 国内镜像优先（dl.google.com 不可达），原源作后备
            maven("https://maven.aliyun.com/repository/google")
            maven("https://maven.aliyun.com/repository/gradle-plugin")
            maven("https://maven.aliyun.com/repository/public")
            google()
            mavenCentral()
            gradlePluginPortal()
        }
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    val onCi = System.getenv("CI") == "true"
    repositories {
        if (onCi) {
            google()
            mavenCentral()
        } else {
            maven("https://maven.aliyun.com/repository/google")
            maven("https://maven.aliyun.com/repository/public")
            google()
            mavenCentral()
        }
    }
}

rootProject.name = "去中心化聊天"
include(":app")
