package chat.dc.app.ui

/** 演示数据：核心（阶段 2）接入前用于撑起真实观感的占位内容，不落盘。 */
object DemoData {
    data class Conversation(
        val id: String,
        val name: String,
        val preview: String,
        val time: String,
        val unread: Int = 0,
        val isGroup: Boolean = false,
    )

    data class Contact(val id: String, val name: String, val letter: Char, val status: String)

    data class Message(val text: String, val sent: Boolean, val time: String)

    val conversations = listOf(
        Conversation("c1", "阿明", "安全码已核对，可以放心聊", "14:32", unread = 2),
        Conversation("c2", "小雨", "动态码扫到了，加一下", "13:05", unread = 1),
        Conversation("g1", "周末爬山（3）", "老王: 装备清单发群里了", "11:47", isGroup = true),
        Conversation("c3", "Bob", "ping", "昨天", unread = 0),
    )

    val contacts = listOf(
        Contact("c1", "阿明", 'A', "在线 · 蓝牙直连"),
        Contact("c2", "小雨", 'X', "离线 · 经信箱中继"),
        Contact("c3", "Bob", 'B', "3 天前"),
    ).sortedBy { it.letter }

    val chatDemo: Map<String, List<Message>> = mapOf(
        "c1" to listOf(
            Message("现在方便说吗？", sent = false, time = "14:30"),
            Message("方便，信号走蓝牙还是中继？", sent = true, time = "14:31"),
            Message("你在我旁边，蓝牙直连，零中继", sent = false, time = "14:32"),
        ),
        "c2" to listOf(
            Message("动态码扫到了，加一下", sent = false, time = "13:05"),
        ),
        "c3" to listOf(
            Message("ping", sent = false, time = "昨天 21:14"),
            Message("pong", sent = true, time = "昨天 21:15"),
        ),
        "g1" to listOf(
            Message("老王: 装备清单发群里了", sent = false, time = "11:47"),
        ),
    )
}
