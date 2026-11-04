//! The hosted server reports this crate's version and the README install tags
//! name the release to depend on, so a version bump must move the tags with it.

use std::path::Path;

fn repo_file(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

#[test]
fn readme_sdk_tags_match_the_crate_version() {
    let tag = format!("tag = \"v{}\"", env!("CARGO_PKG_VERSION"));
    for readme in ["README.md", "sdk/README.md"] {
        let text = repo_file(readme);
        let tags: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("tag = \"v"))
            .collect();
        assert!(!tags.is_empty(), "{readme} names no SDK tag");
        for line in tags {
            assert!(line.contains(&tag), "{readme} has {line:?}, expected {tag}");
        }
    }
}
