# Modification Log: SimpleROHook Fork (2022 Baseline)

This document provides a summary of modifications made to the original `SimpleROHook` source (Upstream: `X-EcutiOnner/SimpleROHook`) to create this performance-optimized and stable baseline for 2022 clients.

## Core 2022 Client Compatibility

### 1. Modern Compiler & Linker Fixes
- **Files**: `Injection.vcxproj`, `SimpleROHook.sln`
- **Original**: The upstream project contained several unresolved symbols and linker errors when compiled on modern MSVC versions.
- **Modification**: Resolved critical linker errors related to `minhook.lib`, Link-Time Code Generation (LTCG), and missing DirectX GUIDs. Updated include/library paths to ensure error-free builds out of the box.

### 2. Signature Scan Restoration
- **File**: `Injection/Core/RoCodeBind.cpp`
- **Modification**: Fixed and re-aligned several engine signature scans that had drifted or were broken in 2022 client executables. This ensures that the hook correctly attaches to 2022 Ragexe functions for NPC and FPS rendering.

## Performance & Stability Enhancements

### 1. High-Speed Diagnostic Rendering
- **File**: `Injection/Core/RoCodeBind.cpp`
- **Original**: Utilized `std::stringstream` for per-actor diagnostic label generation on every frame, which incurred significant memory-allocation overhead.
- **Modification**: Migrated to a high-performance stack-based buffer system using `sprintf_s`. This eliminates per-frame string allocations, significantly reducing CPU usage during rendering.

### 2. Rendering Safety Threshold
- **File**: `Injection/Core/RoCodeBind.cpp`
- **Modification**: Implemented a strict 6-actor rendering limit for diagnostic labels. This provides a definitive safety margin to prevent engine stalls and server disconnects in high-density areas (e.g., crowded towns).

## Aesthetic & Feature Restoration

### 1. Legacy FPS Restoration
- **File**: `Injection/Core/RoCodeBind.cpp`
- **Modification**: Restored the yellow FPS overlay at coordinates `(1135, 185)`. The overlay has been simplified to display the actual FPS only, removing the secondary `TotalTick` counter for a cleaner visual record.

### 2. Stealth Console Mode
- **File**: `Injection/tinyconsole.cpp`
- **Original**: Initialized the debug console with `WS_VISIBLE` in `CreateWindow`, making it appear on every launch.
- **Modification**: Removed the `WS_VISIBLE` flag and explicitly set the initial state to `SW_HIDE`, ensuring a "stealth" client launch while maintaining background logging functionality.

## Status Summary
The current fork is a stable, performance-tuned baseline that is 100% compatible with 2022 Ragnarok client revisions.
