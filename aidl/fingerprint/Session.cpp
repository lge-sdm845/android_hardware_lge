/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Session.h"

#include <hardware/hardware.h>
#include <hardware/hw_auth_token.h>
#include <log/log.h>

#include "CancellationSignal.h"
#include "Legacy2Aidl.h"

namespace aidl {
namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {

void onClientDeath(void* cookie) {
    LOG(INFO) << "FingerprintService has died";
    Session* session = static_cast<Session*>(cookie);
    if (session && !session->isClosed()) {
        session->close();
    }
}

Session::Session(fingerprint_device_t* fp_device, int userId, std::shared_ptr<ISessionCallback> cb,
                 LockoutTracker lockoutTracker)
    : mDevice(fp_device),
      mUserId(userId),
      mSessionCallback(cb),
      mLockoutTracker(lockoutTracker) {
    mDeathRecipient = AIBinder_DeathRecipient_new(onClientDeath);

    int err = 0;
    if (0 != (err =
            mDevice->set_notify(fp_device, Session::notify))) {
        ALOGE("Can't register fingerprint module callback, error: %d", err);
        return nullptr;
    }
    mDevice = fp_device;
}

ndk::ScopedAStatus Session::generateChallenge() {
    uint64_t challenge = mDevice->pre_enroll(mDevice);
    mSessionCallback->onChallengeGenerated(challenge);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::revokeChallenge(int64_t challenge) {
    mDevice->post_enroll(mDevice);
    mSessionCallback->onChallengeRevoked(challenge);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enroll(const HardwareAuthToken& hat, ICancellationSignal* /*_aidl_return*/) {
    hw_auth_token_t authToken;
    translate(hat, authToken);

    int error = ErrorFilter(mDevice->enroll(mDevice, authToken, gid, timeoutSec));
    if(error != 0) {
        ALOGE("enroll() failed: %d", error);
        std::lock_guard<std::mutex> lock(mSessionCallbackMutex);
        mSessionCallback->onError(Error::UNABLE_TO_PROCESS, error);
    }

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticate(int64_t operationId,
                                         std::shared_ptr<ICancellationSignal>* out) {
    int32_t error = mDevice->authenticate(mDevice, operationId, mUserId);

    if (error) {
        ALOGE("authenticate() failed: %d", error);
        std::lock_guard<std::mutex> lock(mSessionCallbackMutex);
        mSessionCallback->onError(Error::UNABLE_TO_PROCESS, error);
    }

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::detectInteraction(std::shared_ptr<ICancellationSignal>* out) {
    ALOGD("Detect interaction is not supported");
    mSessionCallback->onError(Error::UNABLE_TO_PROCESS, 0 /* vendorCode */);

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enumerateEnrollments() {
    int32_t error = mDevice->enumerate(mDevice);

    if (error) {
        ALOGE("enumerate() failed: %d", error);
        std::lock_guard<std::mutex> lock(mSessionCallbackMutex);
        mSessionCallback->onError(Error::UNABLE_TO_PROCESS, error);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::removeEnrollments(const std::vector<int32_t>& enrollmentIds) {
    ALOGI("removeEnrollments, size: %d", enrollmentIds.size());

    for (int32_t enrollment : enrollmentIds) {
        int32_t error = mDevice->remove(mDevice, mUserId, enrollment);
        if (error)
            ALOGE("remove() failed: %d", error);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::getAuthenticatorId() {
    mSessionCallback->onAuthenticatorIdRetrieved(mDevice->get_authenticator_id(mDevice));

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::invalidateAuthenticatorId() {
    mSessionCallback->onAuthenticatorIdInvalidated(mDevice->get_authenticator_id(mDevice));
}

ndk::ScopedAStatus Session::resetLockout(const HardwareAuthToken& /*hat*/) {
    clearLockout(true);
    mIsLockoutTimerAborted = true;

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::close() {
    mClosed = true;
    mSessionCallback->onSessionClosed();
    AIBinder_DeathRecipient_delete(mDeathRecipient);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticateWithContext(
        int64_t operationId, const OperationContext& /*context*/,
        std::shared_ptr<ICancellationSignal>* out) {
    return authenticate(operationId, out);
}

ndk::ScopedAStatus Session::enrollWithContext(const HardwareAuthToken& hat,
                                              const OperationContext& /*context*/,
                                              std::shared_ptr<ICancellationSignal>* out) {
    return enroll(hat, out);
}

ndk::ScopedAStatus Session::detectInteractionWithContext(const OperationContext& /*context*/,
                                              std::shared_ptr<ICancellationSignal>* out) {
    return detectInteraction(out);
}

ndk::ScopedAStatus Session::onContextChanged(const OperationContext& /*context*/) {
    return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
}

// For the following AIDL functions, the interface suggests that
// these should return immediately on non-UDFPS sensors.
ndk::ScopedAStatus Session::onPointerDown(int32_t /*pointerId*/, int32_t /*x*/, int32_t /*y*/, float /*minor*/, float /*major*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUp(int32_t /*pointerId*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onUiReady() {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerDownWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUpWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerCancelWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::setIgnoreDisplayTouches(bool /*shouldIgnore*/) {
    return ndk::ScopedAStatus::ok();
}

void Session::clearLockout(bool clearAttemptCounter) {
    mLockoutTracker.reset(clearAttemptCounter);
    mSessionCallback->onLockoutCleared();
}

void Session::startLockoutTimer(int64_t timeout) {
    mIsLockoutTimerAborted = false;
    std::function<void()> action =
            std::bind(&Session::lockoutTimerExpired, this);
    std::thread([timeout, action]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        action();
    }).detach();

    mIsLockoutTimerStarted = true;
}

void Session::lockoutTimerExpired() {
    if (!mIsLockoutTimerAborted)
        clearLockout(false);

    mIsLockoutTimerStarted = false;
    mIsLockoutTimerAborted = false;
}

// Translate from errors returned by traditional HAL (see fingerprint.h) to
// AIDL-compliant Error.
// NOTE: The equivalent for FINGERPRINT_ERROR_LOCKOUT in AIDL is the `onLockoutPermanent()` 
// callback, and is not part of the Error enum. Thus, it is handled in `notify()` separately.
Error Session::VendorErrorFilter(int32_t error,
            int32_t* vendorCode) {
    *vendorCode = 0;
    switch(error) {
        case FINGERPRINT_ERROR_HW_UNAVAILABLE:
            return Error::HW_UNAVAILABLE;
        case FINGERPRINT_ERROR_UNABLE_TO_PROCESS:
            return Error::UNABLE_TO_PROCESS;
        case FINGERPRINT_ERROR_TIMEOUT:
            return Error::TIMEOUT;
        case FINGERPRINT_ERROR_NO_SPACE:
            return Error::NO_SPACE;
        case FINGERPRINT_ERROR_CANCELED:
            return Error::CANCELED;
        case FINGERPRINT_ERROR_UNABLE_TO_REMOVE:
            return Error::UNABLE_TO_REMOVE;
        default:
            if (error >= FINGERPRINT_ERROR_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = error - FINGERPRINT_ERROR_VENDOR_BASE;
                return Error::VENDOR;
            }
    }
    ALOGE("Unknown error from fingerprint vendor library: %d", error);
    return Error::UNABLE_TO_PROCESS;
}

// Translate acquired messages returned by traditional HAL (see fingerprint.h)
// to AIDL-compliant AcquiredInfo.
AcquiredInfo Session::VendorAcquiredFilter(
        int32_t info, int32_t* vendorCode) {
    *vendorCode = 0;
    switch(info) {
        case FINGERPRINT_ACQUIRED_GOOD:
            return AcquiredInfo::GOOD;
        case FINGERPRINT_ACQUIRED_PARTIAL:
            return AcquiredInfo::PARTIAL;
        case FINGERPRINT_ACQUIRED_INSUFFICIENT:
            return AcquiredInfo::INSUFFICIENT;
        case FINGERPRINT_ACQUIRED_IMAGER_DIRTY:
            return AcquiredInfo::SENSOR_DIRTY;
        case FINGERPRINT_ACQUIRED_TOO_SLOW:
            return AcquiredInfo::TOO_SLOW;
        case FINGERPRINT_ACQUIRED_TOO_FAST:
            return AcquiredInfo::TOO_FAST;
        default:
            if (info >= FINGERPRINT_ACQUIRED_VENDOR_BASE) {
                // vendor specific code.
                *vendorCode = info - FINGERPRINT_ACQUIRED_VENDOR_BASE;
                return AcquiredInfo::VENDOR;
            }
    }
    ALOGE("Unknown acquiredmsg from fingerprint vendor library: %d", info);
    return AcquiredInfo::INSUFFICIENT;
}

void Session::notify(const fingerprint_msg_t *msg) {
    Fingerprint* thisPtr = sInstance;
    std::lock_guard<std::mutex> lock(thisPtr->mSessionCallbackMutex);
    if (thisPtr == nullptr || thisPtr->mSessionCallback == nullptr) {
        ALOGE("Receiving callbacks before the session callback is registered.");
        return;
    }
    const uint64_t devId = reinterpret_cast<uint64_t>(thisPtr->mDevice);
    switch (msg->type) {
        case FINGERPRINT_ERROR: {
                int32_t vendorCode = 0;
                if(FINGERPRINT_ERROR_LOCKOUT == msg->data.error) {
                    ALOGD("onLockoutPermanent()");
                    if (!thisPtr->mSessionCallback->onLockoutPermanent().isOk()) {
                        ALOGE("failed to invoke fingerprint onLockoutPermanent callback");
                    }
                    return;
                }
                Error result = VendorErrorFilter(msg->data.error, &vendorCode);

                ALOGD("onError(%d)", result);
                if (!thisPtr->mSessionCallback->onError(result, vendorCode).isOk()) {
                    ALOGE("failed to invoke fingerprint onError callback");
                }
            }
            break;
        case FINGERPRINT_ACQUIRED: {
                int32_t vendorCode = 0;
                AcquiredInfo result =
                    VendorAcquiredFilter(msg->data.acquired.acquired_info, &vendorCode);
                ALOGD("onAcquired(%d)", result);
                if (!thisPtr->mSessionCallback->onAcquired(result, vendorCode).isOk()) {
                    ALOGE("failed to invoke fingerprint onAcquired callback");
                }
            }
            break;
        case FINGERPRINT_TEMPLATE_ENROLLING:
            ALOGD("onEnrollmentProgress(rem=%d)",
                msg->data.enroll.samples_remaining);
            if (!thisPtr->mSessionCallback->onEnrollmentProgress(
                    msg->data.enroll.samples_remaining).isOk()) {
                ALOGE("failed to invoke fingerprint onEnrollmentProgress callback");
            }
            break;
        case FINGERPRINT_TEMPLATE_REMOVED:
            int removedFingers[] = {msg->data.removed.finger.fid};
            ALOGD("onEnrollmentsRemoved(fid=%d)",
                msg->data.removed.finger.fid);
            if (!thisPtr->mSessionCallback->onEnrollmentsRemoved(removedFingers).isOk()) {
                ALOGE("failed to invoke fingerprint onRemoved callback");
            }
            break;
        case FINGERPRINT_AUTHENTICATED:
            if (msg->data.authenticated.finger.fid != 0) {
                ALOGD("onAuthenticationSucceeded(fid=%d)",
                    msg->data.authenticated.finger.fid);
                const uint8_t* hat =
                    reinterpret_cast<const uint8_t *>(&msg->data.authenticated.hat);
                const hidl_vec<uint8_t> token(
                    std::vector<uint8_t>(hat, hat + sizeof(msg->data.authenticated.hat)));
                if (!thisPtr->mSessionCallback->onAuthenticationSucceeded(
                        msg->data.authenticated.finger.fid,
                        token).isOk()) {
                    ALOGE("failed to invoke fingerprint onAuthenticationSucceeded callback");
                }
            } else {
                // Not a recognized fingerprint
                ALOGD("onAuthenticationFailed()");
                if (!thisPtr->mSessionCallback->onAuthenticationFailed().isOk())
                    ALOGE("failed to invoke fingerprint onAuthenticationFailed callback");
            }
            break;
        case FINGERPRINT_TEMPLATE_ENUMERATING:
            int enumeratedFingers[] = {msg->data.enumerated.finger.fid};
            ALOGD("onEnrollmentsEnumerated(fid=%d)",
                msg->data.enumerated.finger.fid);
            if (!thisPtr->mSessionCallback->onEnrollmentsEnumerated(enumeratedFingers).isOk()) {
                ALOGE("failed to invoke fingerprint onEnrollmentsEnumerated callback");
            }
            break;
    }
}

} // namespace fingerprint
} // namespace biometrics
} // namespace hardware
} // namespace android
} // namespace aidl
