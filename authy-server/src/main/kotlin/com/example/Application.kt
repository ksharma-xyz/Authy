package com.example

import com.google.common.io.BaseEncoding
import io.ktor.http.*
import io.ktor.serialization.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.calllogging.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.Serializable
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

fun main() {
    embeddedServer(Netty, port = 8080) {
        install(ContentNegotiation) {
            json()
        }
        install(CallLogging)

        routing {
            post("/validate") {
                val request = call.receive<ValidationRequest>()
                val isValid = validateTOTP(request.code, request.sharedSecret)
                call.respond(HttpStatusCode.OK, ValidationResponse(isValid))
            }
        }
    }.start(wait = true)
}

@Serializable
data class ValidationRequest(val code: String, val sharedSecret: String)

@Serializable
data class ValidationResponse(val isValid: Boolean)

// TOTP Parameters
const val TIME_STEP_SECONDS = 30
const val VALIDITY_WINDOW = 1  // Allow previous and next window for time drift tolerance

fun validateTOTP(code: String, sharedSecret: String): Boolean {
    val currentTimestamp = System.currentTimeMillis() / 1000

    // Check the current, previous, and next time windows
    for (i in -VALIDITY_WINDOW..VALIDITY_WINDOW) {
        val generatedCode = generateTOTP(sharedSecret, currentTimestamp + i * TIME_STEP_SECONDS)
        if (generatedCode == code) {
            return true
        }
    }
    return false
}

fun generateTOTP(secret: String, timestamp: Long): String {
    val key = BaseEncoding.base32().decode(secret)
    val time = (timestamp / TIME_STEP_SECONDS).toByteArray()

    val mac = Mac.getInstance("HmacSHA1")
    mac.init(SecretKeySpec(key, "HmacSHA1"))
    val hash = mac.doFinal(time)

    val offset = hash.last().toInt() and 0xf
    val binary = ((hash[offset].toInt() and 0x7f) shl 24) or
            ((hash[offset + 1].toInt() and 0xff) shl 16) or
            ((hash[offset + 2].toInt() and 0xff) shl 8) or
            (hash[offset + 3].toInt() and 0xff)

    val otp = binary % 10.0.pow(6).toInt()
    return otp.toString().padStart(6, '0')
}
