/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Fingerprint.h"

#include <fingerprint.sysprop.h>

#include <android-base/properties.h>
#include <android-base/strings.h>
#include <hardware/hardware.h>
#include <hardware/fingerprint.h>
#include <log/log.h>

using namespace ::android::fingerprint::samsung;

using ::android::base::ParseInt;
using ::android::base::Split;

namespace aidl {
namespace android {
namespace hardware {
namespace biometrics {
namespace fingerprint {

constexpr int SENSOR_ID = 0;
constexpr common::SensorStrength SENSOR_STRENGTH = common::SensorStrength::STRONG;
constexpr int MAX_ENROLLMENTS_PER_USER = 5;
constexpr bool SUPPORTS_NAVIGATION_GESTURES = true;
constexpr char HW_COMPONENT_ID[] = "fingerprintSensor";
constexpr char HW_VERSION[] = "lineage/default/legacy";
constexpr char FW_VERSION[] = "1.01";
constexpr char SERIAL_NUMBER[] = "00000001";
constexpr char SW_COMPONENT_ID[] = "matchingAlgorithm";
constexpr char SW_VERSION[] = "lineage/default/legacy";

// Supported fingerprint HAL version
static const uint16_t kVersion = FINGERPRINT_MODULE_API_VERSION_2_1;

Fingerprint::Fingerprint() : mDevice(nullptr) {
    sInstance = this; // keep track of the most recent instance
    mDevice = openHal();
    if (!mDevice) {
        ALOGE("Can't open HAL module");
    }

    std::string sensorTypeProp = FingerprintHalProperties::type().value_or("");
    if (sensorTypeProp == "" || sensorTypeProp == "default" || sensorTypeProp == "rear")
        mSensorType = FingerprintSensorType::REAR;
    else if (sensorTypeProp == "udfps")
        mSensorType = FingerprintSensorType::UNDER_DISPLAY_ULTRASONIC;
    else if (sensorTypeProp == "udfps_optical")
        mSensorType = FingerprintSensorType::UNDER_DISPLAY_OPTICAL;
    else if (sensorTypeProp == "side")
        mSensorType = FingerprintSensorType::POWER_BUTTON;
    else if (sensorTypeProp == "home")
        mSensorType = FingerprintSensorType::HOME_BUTTON;
    else
        mSensorType = FingerprintSensorType::UNKNOWN;

    mMaxEnrollmentsPerUser =
            FingerprintHalProperties::max_enrollments_per_user().value_or(MAX_ENROLLMENTS_PER_USER);
}

ndk::ScopedAStatus Fingerprint::getSensorProps(std::vector<SensorProps>* out) {
    std::vector<common::ComponentInfo> componentInfo = {
            {HW_COMPONENT_ID, HW_VERSION, FW_VERSION, SERIAL_NUMBER, "" /* softwareVersion */},
            {SW_COMPONENT_ID, "" /* hardwareVersion */, "" /* firmwareVersion */,
            "" /* serialNumber */, SW_VERSION}};
    common::CommonProps commonProps = {SENSOR_ID, SENSOR_STRENGTH,
                                       mMaxEnrollmentsPerUser, componentInfo};

    SensorLocation sensorLocation;
    std::string loc = FingerprintHalProperties::sensor_location().value_or("");
    std::vector<std::string> dim = Split(loc, "|");
    if (dim.size() >= 3 && dim.size() <= 4) {
        ParseInt(dim[0], &sensorLocation.sensorLocationX);
        ParseInt(dim[1], &sensorLocation.sensorLocationY);
        ParseInt(dim[2], &sensorLocation.sensorRadius);

        if (dim.size() >= 4)
            sensorLocation.display = dim[3];
    } else if(loc.length() > 0) {
        LOG(WARNING) << "Invalid sensor location input (x|y|radius|display): " << loc;
    }

    LOG(INFO) << "Sensor type: " << ::android::internal::ToString(mSensorType)
              << " location: " << sensorLocation.toString();

    *out = {{commonProps,
             mSensorType,
             {sensorLocation},
             false,
             false,
             false,
             false,
             std::nullopt}};

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Fingerprint::createSession(int32_t /*sensorId*/, int32_t userId,
                                              const std::shared_ptr<ISessionCallback>& cb,
                                              std::shared_ptr<ISession>* out) {
    CHECK(mSession == nullptr || mSession->isClosed()) << "Open session already exists!";

    mSession = SharedRefBase::make<Session>(mDevice, userId, cb);
    *out = mSession;

    mSession->linkToDeath(cb->asBinder().get());

    return ndk::ScopedAStatus::ok();
}

fingerprint_device_t* Fingerprint::openHal() {
    int err;
    const hw_module_t *hw_mdl = nullptr;
    ALOGD("Opening fingerprint hal library...");
    if (0 != (err = hw_get_module(FINGERPRINT_HARDWARE_MODULE_ID, &hw_mdl))) {
        ALOGE("Can't open fingerprint HW Module, error: %d", err);
        return nullptr;
    }

    if (hw_mdl == nullptr) {
        ALOGE("No valid fingerprint module");
        return nullptr;
    }

    fingerprint_module_t const *module =
        reinterpret_cast<const fingerprint_module_t*>(hw_mdl);
    if (module->common.methods->open == nullptr) {
        ALOGE("No valid open method");
        return nullptr;
    }

    hw_device_t *device = nullptr;

    if (0 != (err = module->common.methods->open(hw_mdl, nullptr, &device))) {
        ALOGE("Can't open fingerprint methods, error: %d", err);
        return nullptr;
    }

    if (kVersion != device->version) {
        // enforce version on new devices because of HIDL@2.1 translation layer
        ALOGE("Wrong fp version. Expected %d, got %d", kVersion, device->version);
        return nullptr;
    }

    fingerprint_device_t* fp_device =
        reinterpret_cast<fingerprint_device_t*>(device);

    return fp_device;
}

} // namespace fingerprint
} // namespace biometrics
} // namespace hardware
} // namespace android
} // namespace aidl
