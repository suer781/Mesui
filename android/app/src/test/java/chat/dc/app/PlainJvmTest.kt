package chat.dc.app

import org.junit.Assert.assertEquals
import org.junit.Test

/** 决定性探针：不依赖 Robolectric 的纯 JUnit 测试，验证 worker 类路径本身。 */
class PlainJvmTest {
    @Test
    fun plain_assertion_runs() {
        assertEquals(4, 2 + 2)
    }
}
