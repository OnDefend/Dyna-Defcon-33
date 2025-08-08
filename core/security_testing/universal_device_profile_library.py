#!/usr/bin/env python3
"""
Universal Device Profile Library - AODS Enhanced

Provides realistic, varied device profiles for universal emulator bypass
that works across any APK without hardcoded solutions.

Author: AODS Team
Date: January 2025
"""

import random
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class DeviceCategory(Enum):
    """Device categories for realistic profiling."""
    FLAGSHIP_ANDROID = "flagship_android"
    MID_RANGE = "mid_range"
    BUDGET = "budget"
    TABLETS = "tablets"
    FOLDABLES = "foldables"
    GAMING = "gaming"


@dataclass
class UniversalDeviceProfile:
    """Universal device profile with realistic variation."""
    
    name: str
    fingerprint: str
    model: str
    brand: str
    manufacturer: str
    device: str
    hardware: str
    product: str
    board: str
    bootloader: str
    build_id: str
    version_release: str
    version_sdk: str
    category: DeviceCategory
    security_patch: str
    description: str
    system_properties: Dict[str, str] = field(default_factory=dict)
    
    def get_frida_spoofing_script(self) -> str:
        """Generate Frida JavaScript for device spoofing."""
        return f'''
        Java.perform(function() {{
            console.log("[UNIVERSAL_SPOOF] Applying {self.name} profile");
            
            var Build = Java.use("android.os.Build");
            
            // Apply {self.name} device profile
            Build.FINGERPRINT.value = "{self.fingerprint}";
            Build.MODEL.value = "{self.model}";
            Build.BRAND.value = "{self.brand}";
            Build.MANUFACTURER.value = "{self.manufacturer}";
            Build.DEVICE.value = "{self.device}";
            Build.HARDWARE.value = "{self.hardware}";
            Build.PRODUCT.value = "{self.product}";
            Build.BOARD.value = "{self.board}";
            Build.BOOTLOADER.value = "{self.bootloader}";
            Build.ID.value = "{self.build_id}";
            Build.VERSION.RELEASE.value = "{self.version_release}";
            Build.VERSION.SDK_INT.value = {self.version_sdk};
            Build.VERSION.SECURITY_PATCH.value = "{self.security_patch}";
            
            console.log("[UNIVERSAL_SPOOF] ✅ {self.name} spoofing applied successfully");
        }});
        '''


class UniversalDeviceProfileLibrary:
    """
    Universal Device Profile Library providing realistic device profiles
    for any APK without hardcoded solutions.
    """
    
    def __init__(self):
        """Initialize universal device profile library."""
        self.logger = logging.getLogger(__name__)
        self.profiles = self._load_comprehensive_profiles()
        self.logger.info(f"✅ Universal Device Library initialized with {len(self.profiles)} profiles")
    
    def _load_comprehensive_profiles(self) -> Dict[str, UniversalDeviceProfile]:
        """Load comprehensive device profiles across all categories."""
        profiles = {}
        
        # Samsung Flagship Devices
        profiles.update({
            "samsung_galaxy_s21": UniversalDeviceProfile(
                name="Samsung Galaxy S21 5G",
                fingerprint="samsung/o1sks/o1s:12/SP1A.210812.016/G991BXXU5CVLL:user/release-keys",
                model="SM-G991B",
                brand="samsung",
                manufacturer="samsung",
                device="o1s",
                hardware="exynos2100",
                product="o1sks",
                board="exynos2100",
                bootloader="G991BXXU5CVLL",
                build_id="SP1A.210812.016",
                version_release="12",
                version_sdk="31",
                category=DeviceCategory.FLAGSHIP_ANDROID,
                security_patch="2023-12-01",
                description="Samsung Galaxy S21 5G with Exynos 2100"
            ),
            "samsung_galaxy_s22": UniversalDeviceProfile(
                name="Samsung Galaxy S22 Ultra",
                fingerprint="samsung/dm1qks/dm1q:13/TP1A.220624.014/S908BXXU2AVC4:user/release-keys",
                model="SM-S908B",
                brand="samsung",
                manufacturer="samsung", 
                device="dm1q",
                hardware="exynos2200",
                product="dm1qks",
                board="exynos2200",
                bootloader="S908BXXU2AVC4",
                build_id="TP1A.220624.014",
                version_release="13",
                version_sdk="33",
                category=DeviceCategory.FLAGSHIP_ANDROID,
                security_patch="2024-01-01",
                description="Samsung Galaxy S22 Ultra with Exynos 2200"
            )
        })
        
        # Google Pixel Devices
        profiles.update({
            "pixel_6_pro": UniversalDeviceProfile(
                name="Google Pixel 6 Pro",
                fingerprint="google/raven/raven:13/TQ1A.230105.002/9325679:user/release-keys",
                model="Pixel 6 Pro",
                brand="google",
                manufacturer="Google",
                device="raven",
                hardware="raven",
                product="raven",
                board="raven",
                bootloader="slider-1.2-8893284",
                build_id="TQ1A.230105.002",
                version_release="13",
                version_sdk="33",
                category=DeviceCategory.FLAGSHIP_ANDROID,
                security_patch="2023-12-05",
                description="Google Pixel 6 Pro with Tensor chip"
            ),
            "pixel_7": UniversalDeviceProfile(
                name="Google Pixel 7",
                fingerprint="google/panther/panther:13/TQ1A.230105.002/9325679:user/release-keys",
                model="Pixel 7",
                brand="google",
                manufacturer="Google",
                device="panther",
                hardware="panther",
                product="panther",
                board="panther",
                bootloader="slider-1.3-9034821",
                build_id="TQ1A.230105.002",
                version_release="13",
                version_sdk="33",
                category=DeviceCategory.FLAGSHIP_ANDROID,
                security_patch="2024-01-05",
                description="Google Pixel 7 with Tensor G2"
            )
        })
        
        # OnePlus Devices
        profiles.update({
            "oneplus_9_pro": UniversalDeviceProfile(
                name="OnePlus 9 Pro",
                fingerprint="OnePlus/OnePlus9Pro/OnePlus9Pro:12/RKQ1.201105.002/2203151841:user/release-keys",
                model="LE2125",
                brand="OnePlus",
                manufacturer="OnePlus",
                device="OnePlus9Pro",
                hardware="qcom",
                product="OnePlus9Pro",
                board="kona",
                bootloader="unknown",
                build_id="RKQ1.201105.002",
                version_release="12",
                version_sdk="31",
                category=DeviceCategory.FLAGSHIP_ANDROID,
                security_patch="2023-03-01",
                description="OnePlus 9 Pro with Snapdragon 888"
            ),
            "oneplus_nord": UniversalDeviceProfile(
                name="OnePlus Nord",
                fingerprint="OnePlus/Nord/Nord:11/RKQ1.201105.002/2012100058:user/release-keys",
                model="AC2003",
                brand="OnePlus",
                manufacturer="OnePlus",
                device="Nord",
                hardware="qcom",
                product="Nord",
                board="lito",
                bootloader="unknown",
                build_id="RKQ1.201105.002",
                version_release="11",
                version_sdk="30",
                category=DeviceCategory.MID_RANGE,
                security_patch="2022-12-01",
                description="OnePlus Nord with Snapdragon 765G"
            )
        })
        
        # Xiaomi Devices
        profiles.update({
            "xiaomi_mi_11": UniversalDeviceProfile(
                name="Xiaomi Mi 11",
                fingerprint="Xiaomi/venus/venus:12/RKQ1.200826.002/V13.0.3.0.SKBCNXM:user/release-keys",
                model="M2011K2C",
                brand="Xiaomi",
                manufacturer="Xiaomi",
                device="venus",
                hardware="qcom",
                product="venus",
                board="kona",
                bootloader="unknown",
                build_id="RKQ1.200826.002",
                version_release="12",
                version_sdk="31",
                category=DeviceCategory.FLAGSHIP_ANDROID,
                security_patch="2023-10-01",
                description="Xiaomi Mi 11 with Snapdragon 888"
            ),
            "redmi_note_10": UniversalDeviceProfile(
                name="Redmi Note 10",
                fingerprint="Xiaomi/mojito/mojito:11/RKQ1.200826.002/V12.5.2.0.RKGMIXM:user/release-keys",
                model="M2101K7AG",
                brand="Redmi",
                manufacturer="Xiaomi",
                device="mojito",
                hardware="qcom",
                product="mojito",
                board="bengal",
                bootloader="unknown",
                build_id="RKQ1.200826.002",
                version_release="11",
                version_sdk="30",
                category=DeviceCategory.MID_RANGE,
                security_patch="2022-08-01",
                description="Redmi Note 10 budget-friendly device"
            )
        })
        
        # Budget Devices
        profiles.update({
            "samsung_galaxy_a52": UniversalDeviceProfile(
                name="Samsung Galaxy A52",
                fingerprint="samsung/a52snsxx/a52s:12/SP1A.210812.016/A528BXXU2BVL2:user/release-keys",
                model="SM-A528B",
                brand="samsung",
                manufacturer="samsung",
                device="a52s",
                hardware="mt6853",
                product="a52snsxx",
                board="mt6853",
                bootloader="A528BXXU2BVL2",
                build_id="SP1A.210812.016",
                version_release="12",
                version_sdk="31",
                category=DeviceCategory.MID_RANGE,
                security_patch="2023-11-01",
                description="Samsung Galaxy A52 5G mid-range device"
            )
        })
        
        # Huawei Devices  
        profiles.update({
            "huawei_p30_pro": UniversalDeviceProfile(
                name="Huawei P30 Pro",
                fingerprint="HUAWEI/VOG-L29/HWVOG:10/HUAWEIVOG-L29/10.1.0.162C432:user/release-keys",
                model="VOG-L29",
                brand="HUAWEI",
                manufacturer="HUAWEI",
                device="HWVOG",
                hardware="kirin980",
                product="VOG-L29",
                board="kirin980",
                bootloader="unknown",
                build_id="HUAWEIVOG-L29",
                version_release="10",
                version_sdk="29",
                category=DeviceCategory.FLAGSHIP_ANDROID,
                security_patch="2022-05-01",
                description="Huawei P30 Pro with Kirin 980"
            )
        })
        
        return profiles
    
    def get_random_profile(self, category: Optional[DeviceCategory] = None) -> UniversalDeviceProfile:
        """Get a random realistic device profile."""
        if category:
            filtered_profiles = [p for p in self.profiles.values() if p.category == category]
            if filtered_profiles:
                return random.choice(filtered_profiles)
        
        return random.choice(list(self.profiles.values()))
    
    def get_profile(self, profile_name: str) -> Optional[UniversalDeviceProfile]:
        """Get a specific device profile by name."""
        return self.profiles.get(profile_name)
    
    def get_profiles_by_category(self, category: DeviceCategory) -> List[UniversalDeviceProfile]:
        """Get all profiles in a specific category."""
        return [p for p in self.profiles.values() if p.category == category]
    
    def get_universal_spoofing_script(self, profile_name: Optional[str] = None) -> str:
        """
        Get universal device spoofing script that works with any APK.
        
        Args:
            profile_name: Specific profile name, or None for random selection
            
        Returns:
            Frida JavaScript for universal device spoofing
        """
        if profile_name:
            profile = self.get_profile(profile_name)
            if not profile:
                self.logger.warning(f"Profile {profile_name} not found, using random")
                profile = self.get_random_profile()
        else:
            profile = self.get_random_profile()
        
        return profile.get_frida_spoofing_script()
    
    def get_comprehensive_system_properties(self, profile: UniversalDeviceProfile) -> Dict[str, str]:
        """Get comprehensive system properties for a device profile."""
        return {
            # Device identification
            "ro.product.model": profile.model,
            "ro.product.brand": profile.brand,
            "ro.product.manufacturer": profile.manufacturer,
            "ro.product.device": profile.device,
            "ro.product.board": profile.board,
            "ro.product.name": profile.product,
            "ro.hardware": profile.hardware,
            "ro.build.fingerprint": profile.fingerprint,
            "ro.build.id": profile.build_id,
            "ro.build.display.id": f"{profile.build_id}.{profile.model}",
            "ro.bootloader": profile.bootloader,
            
            # Version information
            "ro.build.version.release": profile.version_release,
            "ro.build.version.sdk": profile.version_sdk,
            "ro.build.version.security_patch": profile.security_patch,
            
            # Security properties
            "ro.secure": "1",
            "ro.debuggable": "0",
            "ro.build.type": "user",
            "ro.build.tags": "release-keys",
            "ro.boot.verifiedbootstate": "green",
            "ro.boot.flash.locked": "1",
            
            # Anti-emulator properties
            "ro.kernel.qemu": "0",
            "init.svc.qemud": "",
            "init.svc.qemu-props": "",
            "qemu.hw.mainkeys": "",
            "qemu.sf.fake_camera": "",
            "ro.bootmode": "unknown",
            
            # Realistic device-specific properties
            f"ro.{profile.brand.lower()}.device": profile.device,
            f"persist.vendor.{profile.brand.lower()}.model": profile.model,
        }
    
    def generate_realistic_android_id(self, profile: UniversalDeviceProfile) -> str:
        """Generate a realistic Android ID for the device profile."""
        # Generate device-specific but realistic Android ID
        import hashlib
        seed = f"{profile.model}_{profile.fingerprint}_{profile.device}"
        return hashlib.md5(seed.encode()).hexdigest()
    
    def list_available_profiles(self) -> Dict[str, List[str]]:
        """List all available profiles by category."""
        categorized = {}
        for category in DeviceCategory:
            categorized[category.value] = [
                p.name for p in self.profiles.values() if p.category == category
            ]
        return categorized


# Global instance for easy access
universal_device_library = UniversalDeviceProfileLibrary()


def get_universal_device_profile(profile_name: Optional[str] = None) -> UniversalDeviceProfile:
    """Get a universal device profile for any APK."""
    return universal_device_library.get_random_profile() if not profile_name else universal_device_library.get_profile(profile_name)


def get_universal_spoofing_script(profile_name: Optional[str] = None) -> str:
    """Get universal device spoofing script for any APK."""
    return universal_device_library.get_universal_spoofing_script(profile_name)


def get_random_android_id() -> str:
    """Get a random realistic Android ID."""
    profile = universal_device_library.get_random_profile()
    return universal_device_library.generate_realistic_android_id(profile)


if __name__ == "__main__":
    # Demo usage
    library = UniversalDeviceProfileLibrary()
    
    print("📱 Universal Device Profile Library Demo")
    print("=" * 50)
    
    # Show available profiles
    profiles = library.list_available_profiles()
    for category, device_list in profiles.items():
        print(f"\n📂 {category.replace('_', ' ').title()}:")
        for device in device_list:
            print(f"   ✅ {device}")
    
    # Random profile demo
    print(f"\n🎲 Random Profile Demo:")
    random_profile = library.get_random_profile()
    print(f"   📱 Selected: {random_profile.name}")
    print(f"   🏷️ Model: {random_profile.model}")
    print(f"   🏢 Brand: {random_profile.brand}")
    print(f"   📊 Category: {random_profile.category.value}")
    
    print(f"\n✅ Universal Device Library Ready for Production!")