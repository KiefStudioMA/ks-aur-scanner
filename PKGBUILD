# Maintainer: Kief Studio <packages@kief.studio>
#
# Local/development PKGBUILD: builds and installs aur-scan from THIS checkout.
# Run `makepkg -si` from the repo root to install your working copy.
#
# The published, distributable packages live under aur/ and are what end users
# install from the AUR:
#   aur/aur-scanner      - tagged releases (primary)
#   aur/ks-aur-scanner   - tagged releases (alias)
#   aur/aur-scanner-git  - rolling, tracks the latest commit
pkgname=aur-scanner
pkgver=1.0.1
pkgrel=1
pkgdesc="Security scanner for Arch Linux AUR packages - detect malicious PKGBUILDs before installation"
arch=('x86_64' 'aarch64')
url="https://github.com/KiefStudioMA/ks-aur-scanner"
license=('GPL-3.0-or-later')
depends=('gcc-libs' 'openssl')
makedepends=('cargo' 'clang')
provides=('aur-scan')
conflicts=('aur-scanner-git' 'ks-aur-scanner')
# No source array: this builds the checked-out tree in place.

pkgver() {
    # Derive the version from the workspace manifest so it never drifts.
    awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$startdir/Cargo.toml"
}

build() {
    cd "$startdir"
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_TARGET_DIR=target
    cargo build --release --all --locked
}

check() {
    cd "$startdir"
    export RUSTUP_TOOLCHAIN=stable
    cargo test --release --all --locked
}

package() {
    cd "$startdir"

    # Binaries
    install -Dm755 "target/release/aur-scan" "$pkgdir/usr/bin/aur-scan"
    install -Dm755 "target/release/aur-scan-wrap" "$pkgdir/usr/bin/aur-scan-wrap"
    install -Dm755 "target/release/aur-scan-hook" "$pkgdir/usr/bin/aur-scan-hook"

    # Shell integration -- the recommended gate. Source it from your shell rc to
    # scan AUR packages BEFORE makepkg builds them.
    install -Dm644 "install/integration.bash" "$pkgdir/usr/share/aur-scan/integration.bash"
    install -Dm644 "install/integration.zsh" "$pkgdir/usr/share/aur-scan/integration.zsh"
    install -Dm644 "install/integration.fish" "$pkgdir/usr/share/aur-scan/integration.fish"

    # Community rules example
    install -Dm644 "install/rules.d/example.toml" "$pkgdir/usr/share/aur-scanner/rules.d/example.toml"

    # pacman hook, shipped as an opt-in example (NOT auto-enabled). It runs after
    # makepkg has already built the package -- prefer the shell integration above.
    install -Dm644 "install/aur-scan.hook" "$pkgdir/usr/share/aur-scan/aur-scan.hook.example"

    # License + docs
    install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm644 "README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
