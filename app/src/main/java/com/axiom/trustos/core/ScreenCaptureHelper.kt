package com.axiom.trustos.core

import android.graphics.Bitmap
import android.os.Build
import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityService.TakeScreenshotCallback
import android.view.Display
import androidx.annotation.RequiresApi

class ScreenCaptureHelper(
    private val service: AccessibilityService
) {

    fun capture(
        onSuccess: (Bitmap) -> Unit,
        onFailure: (Int) -> Unit
    ) {

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            onFailure(-1)
            return
        }

        captureApi30(
            onSuccess,
            onFailure
        )
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun captureApi30(
        onSuccess: (Bitmap) -> Unit,
        onFailure: (Int) -> Unit
    ) {

        service.takeScreenshot(
            Display.DEFAULT_DISPLAY,
            service.mainExecutor,
            object : TakeScreenshotCallback {

                override fun onSuccess(
                    screenshot: AccessibilityService.ScreenshotResult
                ) {

                    val hardwareBuffer =
                        screenshot.hardwareBuffer

                    val colorSpace =
                        screenshot.colorSpace

                    val bitmap = Bitmap.wrapHardwareBuffer(
                        hardwareBuffer,
                        colorSpace
                    )

                    hardwareBuffer.close()

                    if (bitmap == null) {
                        onFailure(-2)
                        return
                    }

                    onSuccess(bitmap)
                }

                override fun onFailure(
                    errorCode: Int
                ) {
                    onFailure(errorCode)
                }
            }
        )
    }
}