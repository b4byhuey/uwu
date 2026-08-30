package com.animesail

import android.annotation.SuppressLint
import android.net.http.SslError
import android.os.Handler
import android.os.Looper
import android.webkit.CookieManager
import android.webkit.SslErrorHandler
import android.webkit.WebView
import android.webkit.WebViewClient
import com.lagradost.cloudstream3.CloudStreamApp
import okhttp3.Interceptor
import okhttp3.Response
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference

class TurnstileInterceptor(private val targetCookie: String = "_as_turnstile") : Interceptor {

    companion object {
        private const val SITE_HOST = "v1.animesail.xyz"
        private const val SITE_ORIGIN = "https://v1.animesail.xyz"
        private const val SITE_USER_AGENT = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36"
    }

    private val savedCookies = ConcurrentHashMap<String, String>()
    private val savedUserAgents = ConcurrentHashMap<String, String>()

    private fun cookieValue(cookieHeader: String): String? {
        return cookieHeader.split("; ")
            .firstOrNull { it.startsWith("$targetCookie=") }
            ?.substringAfter('=')
            ?.takeIf { it.isNotBlank() }
    }

    @SuppressLint("SetJavaScriptEnabled", "WebViewClientOnReceivedSslError")
    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val url = originalRequest.url.toString()
        // Only AnimeSail pages use this site cookie. Do not attach it to extractor hosts.
        if (originalRequest.url.host != SITE_HOST) return chain.proceed(originalRequest)
        val domainUrl = SITE_ORIGIN
        val cookieManager = CookieManager.getInstance()
        val host = originalRequest.url.host
        val captureCookies = {
            cookieManager.flush()
            val cookies = cookieManager.getCookie(SITE_ORIGIN).orEmpty()
            if (cookieValue(cookies) != null) savedCookies[host] = cookies
        }
        cookieManager.setAcceptCookie(true)

        cookieManager.setCookie(domainUrl, "_as_ipin_lc=id-ID; path=/; SameSite=Strict")
        cookieManager.setCookie(domainUrl, "_as_ipin_tz=Asia/Jakarta; path=/; SameSite=Strict")
        cookieManager.setCookie(domainUrl, "_as_ipin_ct=ID; path=/; SameSite=Strict")
        cookieManager.flush()

        val existingCookies = cookieManager.getCookie(domainUrl) ?: ""
        val cachedCookies = savedCookies[host]
        val cookiesToUse = if (cookieValue(existingCookies) != null) existingCookies
        else cachedCookies ?: existingCookies
        val cachedUserAgent = savedUserAgents[host]
        if (cookieValue(cookiesToUse) != null) {
            val response = chain.proceed(
                originalRequest.newBuilder()
                    .header("Cookie", cookiesToUse)
                    .apply { if (!cachedUserAgent.isNullOrBlank()) header("User-Agent", cachedUserAgent) }
                    .build()
            )
            if (response.code != 403 && response.code != 503) return response

            response.close()
            savedCookies.remove(host)
            cookieManager.setCookie(domainUrl, "$targetCookie=; Max-Age=0; path=/; Secure")
            cookieManager.flush()
        }

        val context = CloudStreamApp.context
            ?: return chain.proceed(originalRequest)

        val handler = Handler(Looper.getMainLooper())
        val userAgentRef = AtomicReference(SITE_USER_AGENT)
        val webViewRef = AtomicReference<WebView?>(null)

        handler.post {
            val wv = WebView(context)
            webViewRef.set(wv)

            cookieManager.setAcceptThirdPartyCookies(wv, true)

            wv.settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                databaseEnabled = true
                loadWithOverviewMode = true
                useWideViewPort = true
                userAgentString = SITE_USER_AGENT
            }

            userAgentRef.set(wv.settings.userAgentString)
            savedUserAgents[host] = wv.settings.userAgentString

            wv.webViewClient = object : WebViewClient() {

                override fun onReceivedSslError(
                    view: WebView?,
                    handler: SslErrorHandler?,
                    error: SslError?
                ) {
                    // Never accept invalid certificates. Turnstile must run over valid HTTPS.
                    handler?.cancel()
                }

                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    // The challenge callback may set the cookie immediately before a reload.
                    captureCookies()
                    view?.postDelayed({ captureCookies() }, 250L)
                }
            }

            wv.loadUrl(url)
        }

        // Give the official challenge a bounded window, but never wait indefinitely.
        for (i in 0 until 20) {
            Thread.sleep(1000)
            val cookies = cookieManager.getCookie(SITE_ORIGIN).orEmpty()
            if (cookieValue(cookies) != null) {
                captureCookies()
                break
            }
        }

        handler.post {
            webViewRef.getAndSet(null)?.apply {
                stopLoading()
                destroy()
            }
        }

        captureCookies()
        val finalCookies = cookieManager.getCookie(SITE_ORIGIN).orEmpty()
        val finalUA = userAgentRef.get()

        return chain.proceed(
            originalRequest.newBuilder()
                .apply { if (finalUA.isNotBlank()) header("User-Agent", finalUA) }
                .header("Cookie", finalCookies)
                .build()
        )
    }
}
