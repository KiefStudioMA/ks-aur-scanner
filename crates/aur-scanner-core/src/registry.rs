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
use crate::squat::variant_claim_on;
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
    // Try the LEAST-stripped base first, not the fully-stripped one.
    //
    // `strip_variant_suffixes` loops until nothing is left to remove, and it
    // also eats component suffixes (`-ng`, `-cli`, `-tools`, `-server`...). So
    // `aircrack-ng-git` reduced to `aircrack`, we looked up a package that does
    // not exist, got None, and SQUAT-003 could never fire -- even though the
    // real base `aircrack-ng` is right there. Measured across the live AUR that
    // silenced 573 variants whose base genuinely exists.
    //
    // Peeling one suffix at a time and taking the first base that EXISTS finds
    // `aircrack-ng` before falling through to `aircrack`.
    let mut candidates: Vec<String> = Vec::new();
    {
        let mut cur = name.to_string();
        loop {
            let stripped = strip_one_variant_suffix(&cur);
            match stripped {
                Some(next) if next != cur => {
                    candidates.push(next.clone());
                    cur = next;
                }
                _ => break,
            }
        }
    }
    if candidates.is_empty() {
        return None;
    }
    // Consider each candidate base, nearest first.
    for stem in &candidates {
        // Only a *build*-variant suffix carries a reputation claim; `gcc-libs`
        // is a component of `gcc`, not a claim to be it.
        if variant_claim_on(name, stem).is_none() {
            continue;
        }
        if let Some(base) = base_for(name, stem, official_names, source).await {
            return Some(base);
        }
    }
    None
}

/// Remove exactly ONE trailing variant suffix, or `None` if there is none.
fn strip_one_variant_suffix(name: &str) -> Option<String> {
    crate::squat::variant_suffixes()
        .filter_map(|suffix| {
            name.strip_suffix(suffix)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        // Longest suffix first so `-git-bin` peels predictably.
        .max_by_key(|s| name.len() - s.len())
}

/// Resolve one candidate base name to a `VariantBase`, if it exists.
async fn base_for(
    name: &str,
    stem: &str,
    official_names: &[String],
    source: &dyn PackageInfoSource,
) -> Option<VariantBase> {
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
    async fn finds_the_nearest_existing_base_not_the_fully_stripped_one() {
        // `strip_variant_suffixes` eats component suffixes too, so
        // `aircrack-ng-git` reduced all the way to `aircrack`. Looking up only
        // that missed the real base and silenced SQUAT-003 for 573 live AUR
        // packages whose base genuinely exists.
        let src = source(&[info("aircrack-ng", Some("upstream"))]);
        let base = resolve_variant_base("aircrack-ng-git", &[], &src)
            .await
            .expect("the real base aircrack-ng must be found");
        assert_eq!(base.name, "aircrack-ng");
        assert_eq!(base.maintainer.as_deref(), Some("upstream"));
    }

    #[tokio::test]
    async fn falls_through_to_a_shorter_base_when_the_nearer_one_does_not_exist() {
        let src = source(&[info("tool", Some("alice"))]);
        let base = resolve_variant_base("tool-cli-git", &[], &src)
            .await
            .expect("should fall through to `tool`");
        assert_eq!(base.name, "tool");
    }

    #[tokio::test]
    async fn a_variant_of_an_official_package_is_not_a_reputation_claim() {
        // 4,997 real AUR packages are build variants of an official package.
        // An AUR account is never the same hands as the Arch maintainers, so
        // comparing them would flag every single one of these -- and packaging
        // a git build of a repo package is precisely what the AUR is for.
        // The base MUST exist in the fake registry, or this test passes for the
        // wrong reason: with an empty source the lookup returns None whether or
        // not the official guard is present, and deleting the guard entirely
        // left the whole suite green.
        let src = source(&[
            info("firefox", Some("someone")),
            info("0ad", Some("someone")),
        ]);
        let official = vec!["firefox".to_string(), "0ad".to_string()];
        assert!(
            resolve_variant_base("firefox-bin", &official, &src)
                .await
                .is_none(),
            "an AUR variant of an OFFICIAL package is not a reputation claim"
        );
        assert!(resolve_variant_base("0ad-git", &official, &src)
            .await
            .is_none());

        // Same names, NOT official -> the guard is what makes the difference.
        assert!(
            resolve_variant_base("firefox-bin", &[], &src)
                .await
                .is_some(),
            "without the official list the same lookup must resolve, proving \
             the guard is doing the work"
        );
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
