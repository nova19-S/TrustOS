package com.axiom.trustos.core.privacy

import android.content.Context
import android.content.Intent

class InstalledAppsProvider(
    private val context: Context
) {

    private val packageManager =
        context.packageManager

    private val permissionRiskAnalyzer = PermissionRiskAnalyzer(context)

    fun getInstalledApps(): List<PrivacyApp> {

        val intent = Intent(
            Intent.ACTION_MAIN
        ).apply {
            addCategory(
                Intent.CATEGORY_LAUNCHER
            )
        }

        return packageManager
            .queryIntentActivities(
                intent,
                0
            )
            .map {
                val packageName = it.activityInfo.packageName

                PrivacyApp(
                    packageName = packageName,
                    appName =
                        it.loadLabel(packageManager)
                            .toString(),
                    permissionRisk =
                        permissionRiskAnalyzer.analyze(packageName)
                )
            }
            .distinctBy {
                it.packageName
            }
            .filter {
                it.packageName !=
                        context.packageName
            }
            .sortedBy {
                it.appName.lowercase()
            }
    }
}