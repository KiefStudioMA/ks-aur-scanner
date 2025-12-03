# Maintainer: Kief Studio <packages@kief.studio>
pkgname=aur-scan
pkgver=0.1.0
pkgrel=1
pkgdesc="Security scanner for AUR packages - detect malicious PKGBUILDs before installation"
arch=('x86_64' 'aarch64')
url="https://github.com/KiefStudioMA/ks-aur-scanner"
license=('LicenseRef-Polyform-Noncommercial')
depends=('gcc-libs' 'git')
makedepends=('cargo' 'git')
optdepends=(
    'paru: AUR helper integration'
    'yay: AUR helper integration'
)
provides=('aur-scan' 'aur-scan-wrap' 'aur-scan-hook')
source=("$pkgname-$pkgver.tar.gz::${url}/archive/v${pkgver}.tar.gz")
sha256sums=('SKIP')

build() {
    cd "ks-aur-scanner-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_TARGET_DIR=target
    cargo build --release --locked
}

check() {
    cd "ks-aur-scanner-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo test --release --locked
}

package() {
    cd "ks-aur-scanner-$pkgver"

    # Install binaries
    install -Dm755 target/release/aur-scan "$pkgdir/usr/bin/aur-scan"
    install -Dm755 target/release/aur-scan-wrap "$pkgdir/usr/bin/aur-scan-wrap"
    install -Dm755 target/release/aur-scan-hook "$pkgdir/usr/bin/aur-scan-hook"

    # Install shell integration
    install -Dm644 install/integration.bash "$pkgdir/usr/share/aur-scan/integration.bash"
    install -Dm644 install/integration.zsh "$pkgdir/usr/share/aur-scan/integration.zsh"

    # Install pacman hook (commented out by default - user can enable)
    install -Dm644 install/aur-scan.hook "$pkgdir/usr/share/aur-scan/aur-scan.hook.example"

    # Install license
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"

    # Install documentation
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}

post_install() {
    echo ""
    echo "AUR Security Scanner installed!"
    echo ""
    echo "Quick start:"
    echo "  aur-scan check <package>    # Check AUR package before install"
    echo "  aur-scan system             # Scan all installed AUR packages"
    echo "  aur-scan scan ./PKGBUILD    # Scan a local PKGBUILD"
    echo ""
    echo "For shell integration (auto-scan with paru/yay):"
    echo "  Bash: echo 'source /usr/share/aur-scan/integration.bash' >> ~/.bashrc"
    echo "  Zsh:  echo 'source /usr/share/aur-scan/integration.zsh' >> ~/.zshrc"
    echo ""
    echo "For pacman hook (optional):"
    echo "  sudo cp /usr/share/aur-scan/aur-scan.hook.example /usr/share/libalpm/hooks/aur-scan.hook"
    echo ""
}

post_upgrade() {
    post_install
}
