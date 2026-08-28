package com.axiom.trustos.core.ocr

import android.graphics.Bitmap
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions

class OcrEngine {

    private val recognizer =
        TextRecognition.getClient(
            TextRecognizerOptions.DEFAULT_OPTIONS
        )

    fun recognizeText(
        bitmap: Bitmap,
        onSuccess: (String) -> Unit,
        onFailure: (Exception) -> Unit
    ) {

        val image = InputImage.fromBitmap(
            bitmap,
            0
        )

        recognizer.process(image)
            .addOnSuccessListener { result ->
                onSuccess(result.text)
            }
            .addOnFailureListener { exception ->
                onFailure(exception)
            }
    }

    fun close() {
        recognizer.close()
    }
}