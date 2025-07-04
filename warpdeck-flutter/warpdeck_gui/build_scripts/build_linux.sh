#!/bin/bash

# WarpDeck Linux Production Build Script
# This script builds and packages WarpDeck for Linux distribution

set -e

echo "🐧 Building WarpDeck for Linux..."

# Clean previous builds
echo "🧹 Cleaning previous builds..."
flutter clean
flutter pub get

# Generate code if needed
echo "🔧 Generating code..."
dart run build_runner build --delete-conflicting-outputs

# Build for Linux release
echo "🏗️ Building Flutter app for Linux..."
flutter build linux --release --verbose

BUILD_DIR="build/linux/x64/release/bundle"
APP_NAME="warpdeck_gui"

echo "📦 Preparing Linux distribution..."

# Copy libwarpdeck to the bundle
if [ -f "../../libwarpdeck/build/libwarpdeck.so" ]; then
    echo "📚 Copying libwarpdeck.so to bundle..."
    cp "../../libwarpdeck/build/libwarpdeck.so" "$BUILD_DIR/lib/"
else
    echo "⚠️ Warning: libwarpdeck.so not found. Make sure to build libwarpdeck first."
fi

# Create AppImage structure
echo "🎯 Creating AppImage..."
APPDIR="build/linux/WarpDeck.AppDir"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/lib"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Copy application files
cp -r "$BUILD_DIR"/* "$APPDIR/usr/bin/"
cp -r "$BUILD_DIR/lib"/* "$APPDIR/usr/lib/"

# Create desktop file
cat > "$APPDIR/warpdeck.desktop" << EOF
[Desktop Entry]
Type=Application
Name=WarpDeck
Comment=Cross-platform peer-to-peer file sharing
Exec=warpdeck_gui
Icon=warpdeck
Categories=Network;FileTransfer;
EOF

# Copy desktop file to standard location
cp "$APPDIR/warpdeck.desktop" "$APPDIR/usr/share/applications/"

# === START ICON FIX ===

# Define icon paths
SOURCE_ICON_SVG="assets/icons/warpdeck.svg"
ICON_NAME="warpdeck"
TARGET_ICON_DIR="$APPDIR/usr/share/icons/hicolor/256x256/apps"
TARGET_ICON_PNG="$TARGET_ICON_DIR/${ICON_NAME}.png"

echo "🖼️ Converting SVG to PNG for AppImage compatibility..."

# Check if source icon exists before converting
echo "   -> Checking for source SVG: $SOURCE_ICON_SVG"
ls -l "$SOURCE_ICON_SVG"

# Convert SVG to PNG using rsvg-convert
rsvg-convert -w 256 -h 256 -o "$TARGET_ICON_PNG" "$SOURCE_ICON_SVG"

# The .desktop file uses 'Icon=warpdeck', so 'warpdeck.png' must exist
# in the standard icon path within the AppDir.
echo "   -> Copied PNG to: $TARGET_ICON_PNG"

# It's also good practice to place the icon, named after the app, at the root of the AppDir.
# The AppImage tool often uses this for the AppImage's own icon.
cp "$TARGET_ICON_PNG" "$APPDIR/${ICON_NAME}.png"
echo "   -> Copied PNG to root of AppDir: $APPDIR/${ICON_NAME}.png"

# --- DEBUGGING: List the contents of the key directories ---
echo "--- Verifying file locations ---"
echo "Listing root of AppDir:"
ls -l "$APPDIR"
echo "Listing icon directory:"
ls -l "$TARGET_ICON_DIR"
echo "--- Verification complete ---"

# === END ICON FIX ===


# Create AppRun script
cat > "$APPDIR/AppRun" << 'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="${HERE}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH}"
exec "${HERE}/usr/bin/warpdeck_gui" "$@"
EOF

chmod +x "$APPDIR/AppRun"

# Create Flatpak manifest
echo "📦 Creating Flatpak manifest..."
cat > "build/linux/com.warpdeck.GUI.yaml" << 'EOF'
app-id: com.warpdeck.GUI
runtime: org.freedesktop.Platform
runtime-version: '23.08'
sdk: org.freedesktop.Sdk
command: warpdeck_gui

finish-args:
  - --share=network
  - --socket=wayland
  - --socket=fallback-x11
  - --device=dri
  - --talk-name=org.freedesktop.FileManager1
  - --filesystem=home

modules:
  - name: warpdeck
    buildsystem: simple
    build-commands:
      - cp -r . /app/
    sources:
      - type: dir
        path: ../../
EOF

echo "✅ Linux build complete!"
echo "📍 Bundle: $BUILD_DIR"
echo "📍 AppImage dir: $APPDIR"
echo "📍 Flatpak manifest: build/linux/com.warpdeck.GUI.yaml"

echo ""
echo "📋 Build Information:"
echo "   App Name: WarpDeck"
echo "   Version: 1.0.0"
echo "   Platform: Linux"
echo "   Architecture: x86_64"
echo "   Formats: AppImage, Flatpak"
