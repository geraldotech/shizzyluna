package dev.shizzi

import java.util.concurrent.atomic.AtomicBoolean

sealed interface VpnBinding {

    data class Adopted(val handle: Long) : VpnBinding

    data class Lost(val problem: String) : VpnBinding
}

fun interface VpnLocator {

    fun currentVpnHandle(): Long
}

class VpnWatchdog(
    private val locator: VpnLocator,
    @Volatile var stopOnLoss: Boolean = true,
    private val onStrike: ((strike: Int, boundHandle: Long) -> Unit)? = null,
    private val onStrikeRecovered: ((boundHandle: Long) -> Unit)? = null,
    private val onChange: (VpnBinding) -> Unit,
) {

    private val isRunning = AtomicBoolean(false)
    private var thread: Thread? = null

    var boundHandle = UNBOUND
        private set

    var consecutiveMisses = 0
        private set

    var isWaitingForRecovery = false
        private set

    fun adoptCurrentVpn(): Long {
        boundHandle = locator.currentVpnHandle()
        consecutiveMisses = 0
        isWaitingForRecovery = false
        return boundHandle
    }

    /**
     * Marks a rebind attempt as failed so the next poll cycle will re-emit [VpnBinding.Adopted]
     * for the active VPN handle instead of treating it as already bound (`V10`).
     */
    fun markRebindFailed() {
        boundHandle = UNBOUND
        isWaitingForRecovery = true
    }

    fun start() {
        if (!isRunning.compareAndSet(false, true)) return

        thread = Thread({ monitor() }, "vpn-watchdog").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        isRunning.set(false)

        val watcher = thread
        thread = null
        if (watcher != null && watcher != Thread.currentThread()) watcher.interrupt()
    }

    private fun monitor() {
        while (isRunning.get()) {
            val didSleep = runCatching { Thread.sleep(POLL_INTERVAL_MS) }.isSuccess
            if (!didSleep || !isRunning.get()) return

            val binding = evaluate() ?: continue
            val shouldStop = binding is VpnBinding.Lost && stopOnLoss
            if (shouldStop) {
                isRunning.set(false)
            }

            onChange(binding)
            if (shouldStop) return
        }
    }

    internal fun evaluate(): VpnBinding? {
        val observed = locator.currentVpnHandle()

        if (observed != UNBOUND) return adopt(observed)

        if (boundHandle == UNBOUND) return null

        consecutiveMisses++
        if (consecutiveMisses < MISSES_BEFORE_TEARDOWN) {
            SessionLog.warn(
                "vpn strike $consecutiveMisses/$MISSES_BEFORE_TEARDOWN: " +
                    "no VPN present, session is bound to $boundHandle",
            )
            onStrike?.invoke(consecutiveMisses, boundHandle)
            return null
        }

        // Confirmed VPN loss after debounce: reset boundHandle to UNBOUND so that when the VPN
        // reconnects with either a new handle (V03) or the same handle (V04), adopt(observed)
        // recognizes the transition and emits VpnBinding.Adopted(observed), and subsequent polls
        // during the same outage do not spam duplicate Lost events.
        boundHandle = UNBOUND
        consecutiveMisses = 0
        isWaitingForRecovery = true
        val detailMessage = if (stopOnLoss) {
            VPN_LOST_DETAIL
        } else {
            VPN_WAITING_FOR_RECOVERY_DETAIL
        }
        return VpnBinding.Lost(detailMessage)
    }

    private fun adopt(observed: Long): VpnBinding? {
        val hadStrikes = consecutiveMisses > 0
        consecutiveMisses = 0
        if (observed == boundHandle) {
            if (hadStrikes) {
                onStrikeRecovered?.invoke(boundHandle)
            }
            return null
        }

        val previous = boundHandle
        val wasWaiting = isWaitingForRecovery
        boundHandle = observed
        isWaitingForRecovery = false
        SessionLog.info(adoptionMessage(previous, observed, wasWaiting))
        return VpnBinding.Adopted(observed)
    }

    private fun adoptionMessage(previous: Long, adopted: Long, wasWaiting: Boolean): String = when {
        wasWaiting -> "vpn recovered: re-pinning the datapath to handle $adopted"
        previous == UNBOUND -> "vpn adopted: pinning the datapath to handle $adopted"
        else -> "vpn replaced: handle $previous is gone, re-pinning to $adopted"
    }

    companion object {
        const val UNBOUND = 0L
        const val POLL_INTERVAL_MS = 5_000L

        const val MISSES_BEFORE_TEARDOWN = 2

        const val VPN_LOST_DETAIL =
            "VPN disconnected. Session stopped to keep devices protected."

        const val VPN_WAITING_FOR_RECOVERY_DETAIL =
            "VPN disconnected — waiting for reconnection"
    }
}

