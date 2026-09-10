//! Assembling the registry view of a package before it is scanned.
//!
//! Ownership questions -- who publishes this, how long has it existed, is this
//! really upstream's own binary build -- cannot be answered from a PKGBUILD.
//! They need the package registry. This module gathers that view once, from the
//! AUR RPC result the caller already has plus the local pacman databases, and
//! hands it to the analyzers as a [`RegistryContext`].
//!
//! Every lookup here degrades to "unknown" rather than failing the scan. A
//! network hiccup must never turn into a finding about a maintainer.

use crate::aur::{official_package_names, AurPackageInfo, PackageInfoSource};
use crate::squat::{strip_variant_suffixes, variant_claim_on};
use crate::types::{RegistryContext, VariantBase};
use tracing::debug;

/// Build the registry view for `package` from an AUR RPC record.
///
/// `official_names` is passed in rather than read here so a multi-package scan
/// pays for the pacman query once. Use [`load_official_names`] to obtain it.
pub async fn context_for(
    package: &AurPackageInfo,
    official_names: Vec<String>,
    source: &dyn PackageInfoSource,
) -> RegistryContext {
    let variant_base = resolve_variant_base(&package.name, &official_names, source).await;
    RegistryContext {
        maintainer: package.maintainer.clone(),
        num_votes: package.num_votes,
        popularity: package.popularity,
        out_of_date: package.out_of_date,
        first_submitted: package.first_submitted,
        last_modified: package.last_modified,
        official_names,
        variant_base,
    }
}

/// The official-repository package names, for name comparison. Empty when the
/// sync databases cannot be read.
pub async fn load_official_names() -> Vec<String> {
    let names = official_package_names().await;
    debug!("loaded {} official package names", names.len());
    names
}

/// If `name` is a build variant of another package (`foo-bin` of `foo`), look up
/// what the registry says about that base package.
///
/// Checks the official repositories first -- a `-bin` of a repo package is the
/// strongest form of the claim -- then the AUR. Returns `None` when the name is
/// not a variant shape at all, or when the base package simply does not exist,
/// which is the ordinary case for a package that merely happens to end in
/// `-bin`.
async fn resolve_variant_base(
    name: &str,
    official_names: &[String],
    source: &dyn PackageInfoSource,
) -> Option<VariantBase> {
    let stem = strip_variant_suffixes(name);
    if stem == name {
        return None;
    }
    // Only a *build*-variant suffix carries a reputation claim; `gcc-libs` is a
    // component of `gcc`, not a claim to be it.
    variant_claim_on(name, stem)?;

    // A base package in the official repositories is deliberately NOT treated
    // as a variant base.
    //
    // An AUR account is never the same "hands" as the Arch package maintainers,
    // so a maintainer comparison against an official base is true by
    // construction and says nothing. Measured against the live AUR, 4,997
    // packages are build variants of an official package -- `0ad-git`,
    // `acl-git`, `abiword-git` -- and every one of them would be flagged.
    // Packaging a git build of a repo package is what the AUR is *for*.
    if official_names.iter().any(|n| n == stem) {
        debug!("{name:?} is a variant of official {stem:?}; not a reputation claim");
        return None;
    }

    // An AUR base package: `aur-scanner-bin` against AUR `aur-scanner`.
    match source.info_batch(&[stem]).await {
        Ok(infos) => infos
            .into_iter()
            .find(|i| i.name == stem)
            .map(|base| VariantBase {
                name: base.name,
                maintainer: base.maintainer,
                official: false,
                num_votes: base.num_votes,
            }),
        Err(e) => {
            // Unknown base means we cannot say whose hands it is in, so we say
            // nothing rather than guessing.
            debug!("could not resolve variant base {stem:?} for {name:?}: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use std::collections::HashMap;

    struct FakeSource(HashMap<String, AurPackageInfo>);

    #[async_trait::async_trait]
    impl PackageInfoSource for FakeSource {
        async fn info_batch(&self, names: &[&str]) -> Result<Vec<AurPackageInfo>> {
            Ok(names
                .iter()
                .filter_map(|n| self.0.get(*n).cloned())
                .collect())
        }
    }

    fn info(name: &str, maintainer: Option<&str>) -> AurPackageInfo {
        AurPackageInfo {
            name: name.into(),
            version: "1.0-1".into(),
            description: None,
            maintainer: maintainer.map(String::from),
            num_votes: Some(10),
            popularity: Some(1.0),
            out_of_date: None,
            first_submitted: Some(1_700_000_000),
            last_modified: Some(1_700_000_000),
            package_base: name.into(),
            depends: vec![],
            make_depends: vec![],
            check_depends: vec![],
            opt_depends: vec![],
            provides: vec![],
        }
    }

    fn source(entries: &[AurPackageInfo]) -> FakeSource {
        FakeSource(
            entries
                .iter()
                .map(|i| (i.name.clone(), i.clone()))
                .collect(),
        )
    }

    #[tokio::test]
    async fn resolves_an_aur_base_for_a_bin_variant() {
        let src = source(&[info("aur-scanner", Some("kiefstudio"))]);
        let base = resolve_variant_base("aur-scanner-bin", &[], &src)
            .await
            .expect("base must resolve");
        assert_eq!(base.name, "aur-scanner");
        assert_eq!(base.maintainer.as_deref(), Some("kiefstudio"));
        assert!(!base.official);
    }

    #[tokio::test]
    async fn a_variant_of_an_official_package_is_not_a_reputation_claim() {
        // 4,997 real AUR packages are build variants of an official package.
        // An AUR account is never the same hands as the Arch maintainers, so
        // comparing them would flag every single one of these -- and packaging
        // a git build of a repo package is precisely what the AUR is for.
        let src = source(&[]);
        let official = vec!["firefox".to_string(), "0ad".to_string()];
        assert!(resolve_variant_base("firefox-bin", &official, &src)
            .await
            .is_none());
        assert!(resolve_variant_base("0ad-git", &official, &src)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn a_non_variant_name_has_no_base() {
        let src = source(&[info("python", Some("someone"))]);
        assert!(resolve_variant_base("python-requests", &[], &src)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn a_component_suffix_is_not_a_variant_base() {
        let src = source(&[info("gcc", Some("someone"))]);
        assert!(resolve_variant_base("gcc-libs", &[], &src).await.is_none());
    }

    #[tokio::test]
    async fn a_missing_base_package_yields_nothing() {
        // `something-bin` where no `something` exists is just a package name.
        let src = source(&[]);
        assert!(resolve_variant_base("something-bin", &[], &src)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn context_carries_registry_fields_through() {
        let src = source(&[]);
        let pkg = info("mytool", Some("alice"));
        let ctx = context_for(&pkg, vec!["firefox".into()], &src).await;
        assert_eq!(ctx.maintainer.as_deref(), Some("alice"));
        assert_eq!(ctx.num_votes, Some(10));
        assert_eq!(ctx.official_names, vec!["firefox".to_string()]);
        assert!(ctx.variant_base.is_none());
    }
}
