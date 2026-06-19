# Inert install hook present only so the loader finds the file referenced by the
# non-standard `install=postinstall.hook.sh` (which itself trips META-005 for
# not being a plain <name>.install). Deliberately does nothing.
post_install() {
    :
}

post_upgrade() {
    :
}
