package app.template.patches.aviate.premium

import app.morphe.patcher.patch.rawResourcePatch
import app.template.patches.shared.hermesPatch
import app.morphe.patcher.extensions.InstructionExtensions.addInstruction
import app.morphe.patcher.patch.bytecodePatch
import app.template.patches.shared.returnEarly
import app.template.patches.shared.Constants.AVIATE_COMPATIBILITY

/**
 * Patches four Hermes bytecode sites in the React Native bundle (HBC v98).
 *
 * Root cause analysis:
 * The subscription gate has two independent paths:
 *   A) React context: SubscriptionProvider (fn #7763) seeds isPro=false via useState(false),
 *      then fn #15987 (state-update callback) is invoked by the API response and
 *      overwrites state. Server returns subscription="free" for free users.
 *   B) AsyncStorage path: isProUser (fn #6791) reads offline_subscription_state
 *      from device storage — used by widgets and native modules outside React context.
 *
 * Fix strategy (all anchors are stable non-obfuscated function names + unique byte windows):
 *   1. Seed isPro=true at first render (SubscriptionProvider useState seed, fn #7763 +0x4d):
 *      Flip LoadConstFalse r2 (0x96 02) -> LoadConstTrue r2 (0x95 02) for the isPro
 *      useState(false) call. No "free" flash on first render.
 *   2. No-op the state-update callback (fn #15987, offset 0x00622370):
 *      Returns undefined immediately so the API response never overwrites our
 *      seeded isPro=true. This is the critical fix — without it, server always
 *      resets subscription="free" for free users.
 *   3. Return true from computeIsPro (fn #7761, offset 0x004ee8ea):
 *      Belt-and-suspenders cover for any caller that bypasses SubscriptionProvider.
 *   4. Return true from isProUser (fn #6791, offset 0x004c885e):
 *      Covers widgets and native-module paths that read offline_subscription_state.
 *
 * HBC v98 opcodes (verified from hbc98.py opcode table):
 *   0x76 Reg8        = Ret
 *   0x93 Reg8        = LoadConstUndefined
 *   0x95 Reg8        = LoadConstTrue
 *   0x96 Reg8        = LoadConstFalse
 *
 * All four patterns are unique in the bundle (verified by exhaustive search).
 * SHA-1 footer is recalculated by hermesPatch automatically.
 *
 * Version history:
 *   v1.0.1 (versionCode=201): fn #6699, #7657, #7659, #15648 (old offsets)
 *   v1.1.0-beta.1 (versionCode=202): fn #6791, #7761, #7763, #15987 (current)
 *   v1.4.2 (versionCode=219): fn #16932, #23615, #7483 — see AviatePremiumPatch_142.kt
 *     and INSTRUCTIONS_142.md. The 1.1.0 patterns below DO NOT exist in 1.4.2;
 *     the subscription module was restructured (useState initializer is now
 *     hydrateSubscriptionData fn #7811, which returns a full snapshot object).
 */


private const val LICENSE_CLIENT = "Lcom/pairip/licensecheck/LicenseClient;"
private const val LICENSE_CHECK_STATE = "Lcom/pairip/licensecheck/LicenseClient\$LicenseCheckState;"

private val  aviateLicensePatch = bytecodePatch(default = false){
    compatibleWith(AVIATE_COMPATIBILITY)

    execute {
        // 1. Force responseCode=LICENSED (0x0) before processResponse branches on it.
        //    Without this, re-signed APKs receive NOT_LICENSED and are killed.
        ProcessLicenseResponseFingerprint.method.addInstruction(
            0,
            "const/4 p1, 0x0"
        )

        // 2. Skip cryptographic signature validation.
        //    validateResponse() always throws LicenseCheckException on re-signed APKs
        //    because the APK signature no longer matches the original certificate.
        ValidateLicenseResponseFingerprint.method.returnEarly()

        // 3. Block the license check at the entry point.
        //    checkLicense(Context) is the public API called at app startup.
        //    Returning early prevents any connection to Google Play licensing service.
        CheckLicenseFingerprint.method.returnEarly()
    }
}


@Suppress("unused")
val aviatePremiumPatch = rawResourcePatch(
    name = "Unlock Pro",
    description = "Unlocks Aviate Pro and Lifetime Pro by patching the Hermes JS subscription gate."
) {
    compatibleWith(AVIATE_COMPATIBILITY)

    dependsOn(aviateLicensePatch , hermesPatch {
        // ===== Aviate 1.4.2 (versionCode=219, HBC v98, instOffset=0x427424) =====
        // Every pattern verified to appear EXACTLY ONCE in the 1.4.2 bundle and
        // every replacement is byte-length-preserving. Offsets refer to the file
        // layout in aviate-1.4.2/extracted/assets/index.android.bundle.

        // 1. Hydration / refresh callback no-op (closure fn #16932 @ 0x6f3c3c).
        //    In 1.4.2 the SubscriptionProvider useState initializer is
        //    hydrateSubscriptionData (fn #7811), which returns a whole entitlement
        //    snapshot object — there is no single LoadConstFalse seed to flip.
        //    Instead we no-op the callback that recomputes and STORES the
        //    entitlement, so the pro state is never overwritten with a "free"
        //    snapshot. This is the 1.1.0 analogue of the fn #15987 no-op.
        //    Replace first 4 bytes with 93 00 76 00 (LoadConstUndefined r0, Ret r0).
        val refreshCallbackNoop =
            "89 04 02 93 00 D5 06 04 00 04 04 34" to
            "93 00 76 00 00 D5 06 04 00 04 04 34"

        // 2. effectiveNativeAccess selector -> true (closure fn #23615 @ 0x79e8c5).
        //    1.4.2 analogue of computeIsPro: the selector every Pro consumer
        //    reads through useSubscription() / useProEntitlement(). The whole
        //    42-byte body is required for uniqueness (the first 4 bytes alone
        //    appear 474 times). Replace first 4 bytes with 95 00 76 00
        //    (LoadConstTrue r0, Ret r0).
        val computeIsPro =
            "34 03 01 3B 02 03 09 93 00 6C 02 02 00 34 04 00 3B 04 04 01 6E 04 04 00 02 3B 03 03 0A 45 02 02 00 1F E2 6E 01 03 00 02 76 00" to
            "95 00 76 00 02 03 09 93 00 6C 02 02 00 34 04 00 3B 04 04 01 6E 04 04 00 02 3B 03 03 0A 45 02 02 00 1F E2 6E 01 03 00 02 76 00"

        // 3. isProUser -> true (fn #7483 @ 0x5784e3; offline AsyncStorage path —
        //    widget / native bridge). Replace first 4 bytes with 95 00 76 00.
        val isProUser =
            "93 03 93 06 93 00 93 01" to
            "95 00 76 00 93 00 93 01"

        setOf(refreshCallbackNoop, computeIsPro, isProUser)
    })
}