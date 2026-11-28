//! Publish Seren's official public starter skills using MCP's Skills extension.

use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use rmcp::{
    ErrorData as McpError,
    model::{
        CacheScope, GetSkillResult, ListSkillsResult, ReadResourceResult, ResourceContents,
        SKILL_MD, Skill, SkillFrontmatter, SkillResource, SkillResources,
    },
};
use serde::Deserialize;
use tokio::sync::Mutex;
use uuid::Uuid;

const API_ORIGIN: &str = "https://api.serendb.com";
const SEREN_ORGANIZATION: Uuid = Uuid::from_u128(0x29);
const GUIDE_PATH: &str = "/publishers/seren-agent/skill.md";
const URI_ROOT: &str = "skill://seren/";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const CATALOG_TTL: Duration = Duration::from_secs(60);
const RETRY_AFTER: Duration = Duration::from_secs(10);

static CATALOG: LazyLock<Result<Catalog>> = LazyLock::new(|| Catalog::new(API_ORIGIN));

pub(crate) fn catalog() -> Result<&'static Catalog, McpError> {
    CATALOG.as_ref().map_err(unavailable)
}

fn unavailable(error: &anyhow::Error) -> McpError {
    tracing::warn!(%error, "Seren skills catalog unavailable");
    catalog_unavailable()
}

fn catalog_unavailable() -> McpError {
    McpError::internal_error("Seren skills catalog unavailable", None)
}

pub(crate) struct Catalog {
    origin: String,
    client: reqwest::Client,
    cached: Mutex<Cache>,
}

#[derive(Default)]
enum Cache {
    #[default]
    Empty,
    Ready(Arc<Snapshot>),
    Failed(Instant),
}

struct Snapshot {
    fetched_at: Instant,
    skills: Vec<ServedSkill>,
}

impl Snapshot {
    fn ttl_ms(&self) -> u64 {
        CATALOG_TTL
            .saturating_sub(self.fetched_at.elapsed())
            .as_millis() as u64
    }
}

struct ServedSkill {
    skill: Skill,
    files: BTreeMap<String, ResourceContents>,
}

#[derive(Deserialize)]
struct Download {
    data: Bundle,
}

#[derive(Deserialize)]
struct Bundle {
    skill: Owner,
    skill_md: String,
    #[serde(default)]
    files: Vec<BundleFile>,
}

#[derive(Deserialize)]
struct Owner {
    slug: String,
    owner_kind: Option<String>,
    owner_organization_id: Option<Uuid>,
}

#[derive(Deserialize)]
struct BundleFile {
    path: String,
    content_b64: String,
}

impl Catalog {
    fn new(origin: &str) -> Result<Self> {
        Ok(Self {
            origin: origin.to_owned(),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?,
            cached: Mutex::default(),
        })
    }

    async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let mut response = self
            .client
            .get(format!("{}{path}", self.origin))
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "{path}: HTTP {}",
            response.status()
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                chunk.len() <= MAX_RESPONSE_BYTES - bytes.len(),
                "Skill response is too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn fetch_bundle(&self, slug: &str, name: &str) -> Result<ServedSkill> {
        let path = format!("/publishers/seren-skills/skills/{slug}/download");
        let bundle = serde_json::from_slice::<Download>(&self.get(&path).await?)?.data;
        ensure!(
            bundle.skill.slug == slug
                && bundle.skill.owner_kind.as_deref() == Some("organization")
                && bundle.skill.owner_organization_id == Some(SEREN_ORGANIZATION),
            "Unexpected catalog owner or slug for {slug}"
        );
        let served = ServedSkill::new(bundle.skill_md, bundle.files)?;
        ensure!(
            served.skill.name() == name,
            "Unexpected skill name for {slug}"
        );
        Ok(served)
    }

    async fn fetch_agent_guide(&self) -> Result<ServedSkill> {
        let markdown = String::from_utf8(self.get(GUIDE_PATH).await?)?;
        let guide = ServedSkill::new(markdown, Vec::new())?;
        ensure!(
            guide.skill.name() == "seren-agent",
            "Unexpected Seren Agent guide name"
        );
        Ok(guide)
    }

    async fn snapshot(&self) -> Result<Arc<Snapshot>, McpError> {
        let mut cached = self.cached.lock().await;
        match &*cached {
            Cache::Ready(snapshot) if snapshot.ttl_ms() != 0 => {
                return Ok(Arc::clone(snapshot));
            }
            Cache::Failed(when) if when.elapsed() < RETRY_AFTER => {
                return Err(catalog_unavailable());
            }
            _ => {}
        }
        let fetched = tokio::try_join!(
            self.fetch_bundle("seren-api", "api"),
            self.fetch_agent_guide(),
            self.fetch_bundle("seren-seren-publishers", "seren-publishers"),
            self.fetch_bundle("seren-seren-db", "seren-db"),
        );
        let (api, agent, publishers, db) = match fetched {
            Ok(skills) => skills,
            Err(error) => {
                *cached = Cache::Failed(Instant::now());
                return Err(unavailable(&error));
            }
        };
        let snapshot = Arc::new(Snapshot {
            fetched_at: Instant::now(),
            skills: vec![api, agent, publishers, db],
        });
        *cached = Cache::Ready(Arc::clone(&snapshot));
        Ok(snapshot)
    }

    pub(crate) async fn list(&self) -> Result<ListSkillsResult, McpError> {
        let snapshot = self.snapshot().await?;
        let skills = snapshot
            .skills
            .iter()
            .map(|entry| entry.skill.clone())
            .collect();
        Ok(ListSkillsResult::with_all_items(skills)
            .with_ttl_ms(snapshot.ttl_ms())
            .with_cache_scope(CacheScope::Public))
    }

    pub(crate) async fn skill(&self, uri: &str) -> Result<GetSkillResult, McpError> {
        if !uri.starts_with(URI_ROOT) {
            return Err(McpError::invalid_params("Unknown Seren skill URI", None));
        }
        let snapshot = self.snapshot().await?;
        let entry = snapshot
            .skills
            .iter()
            .find(|entry| entry.skill.uri == uri)
            .ok_or_else(|| McpError::invalid_params("Unknown Seren skill URI", None))?;
        Ok(GetSkillResult::new(entry.skill.clone())
            .with_ttl_ms(snapshot.ttl_ms())
            .with_cache_scope(CacheScope::Public))
    }

    pub(crate) async fn read(&self, uri: &str) -> Result<ReadResourceResult, McpError> {
        let not_found = || McpError::resource_not_found("Unknown Seren skill resource", None);
        if !uri.starts_with(URI_ROOT) {
            return Err(not_found());
        }
        let snapshot = self.snapshot().await?;
        let content = snapshot
            .skills
            .iter()
            .find_map(|entry| entry.files.get(uri))
            .ok_or_else(not_found)?;
        Ok(ReadResourceResult::new(vec![content.clone()])
            .with_ttl_ms(snapshot.ttl_ms())
            .with_cache_scope(CacheScope::Public))
    }
}

impl ServedSkill {
    fn new(markdown: String, supporting_files: Vec<BundleFile>) -> Result<Self> {
        let frontmatter = parse_frontmatter(&markdown)?;
        let root = format!("{URI_ROOT}{}/", urlencoding::encode(&frontmatter.name));
        let uri = format!("{root}{SKILL_MD}");
        let mut resources = vec![SkillResource::from_bytes(&uri, markdown.as_bytes())];
        let mut files = BTreeMap::from([(
            uri.clone(),
            ResourceContents::text(markdown, &uri).with_mime_type("text/markdown"),
        )]);
        for file in supporting_files {
            let mut segments = Vec::new();
            for segment in file.path.split('/') {
                if segment.is_empty() || segment.starts_with('.') || segment.contains('\\') {
                    bail!("Unsafe skill resource path");
                }
                segments.push(urlencoding::encode(segment));
            }
            let uri = format!("{root}{}", segments.join("/"));
            ensure!(!files.contains_key(&uri), "Duplicate skill resource");
            let bytes = STANDARD.decode(file.content_b64)?;
            resources.push(SkillResource::from_bytes(&uri, &bytes));
            let content = match std::str::from_utf8(&bytes) {
                Ok(text) if !text.contains('\0') => ResourceContents::text(text, &uri),
                _ => ResourceContents::blob(STANDARD.encode(&bytes), &uri)
                    .with_mime_type("application/octet-stream"),
            };
            files.insert(uri, content);
        }
        let skill = Skill::new(uri, frontmatter, SkillResources::Files(resources));
        skill.validate()?;
        Ok(Self { skill, files })
    }
}

fn parse_frontmatter(markdown: &str) -> Result<SkillFrontmatter> {
    let mut lines = markdown.lines();
    ensure!(
        lines.next().map(str::trim_end) == Some("---"),
        "Skill has no YAML frontmatter"
    );
    let mut metadata = String::new();
    for line in lines {
        if line.trim_end() == "---" {
            let frontmatter: SkillFrontmatter =
                yaml_serde::from_str(&metadata).context("Invalid skill frontmatter")?;
            ensure!(
                !frontmatter.description.trim().is_empty(),
                "Skill has no description"
            );
            return Ok(frontmatter);
        }
        metadata.push_str(line);
        metadata.push('\n');
    }
    bail!("Skill frontmatter is not closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    async fn mock_catalog(server: &MockServer, api_owner: Uuid) {
        for (slug, name) in [
            ("seren-api", "api"),
            ("seren-seren-publishers", "seren-publishers"),
            ("seren-seren-db", "seren-db"),
        ] {
            let owner = if slug == "seren-api" {
                api_owner
            } else {
                SEREN_ORGANIZATION
            };
            let response = Mock::given(method("GET"))
                .and(path(format!("/publishers/seren-skills/skills/{slug}/download")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": {
                        "skill": {"slug": slug, "owner_kind": "organization", "owner_organization_id": owner},
                        "skill_md": format!("---\nname: {name}\ndescription: Official instructions\n---\nRead the reference.\n"),
                        "files": [{"path": "references/test.bin", "content_b64": "YQBi"}]
                    }
                })))
                ;
            if slug == "seren-api" || api_owner == SEREN_ORGANIZATION {
                response.expect(1).mount(server).await;
            } else {
                response.expect(..=1).mount(server).await;
            }
        }
        Mock::given(method("GET"))
            .and(path(GUIDE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "---\nname: seren-agent\ndescription: Managed agents\n---\nGuide\n",
            ))
            .expect(..=1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn discovery_and_reads_share_the_same_public_catalog_snapshot() {
        let server = MockServer::start().await;
        let catalog = Catalog::new(&server.uri()).unwrap();
        mock_catalog(&server, SEREN_ORGANIZATION).await;
        assert!(catalog.read("file:///local-skill.txt").await.is_err());
        let list = catalog.list().await.unwrap();
        assert_eq!(
            list.skills
                .iter()
                .map(|skill| skill.name())
                .collect::<Vec<_>>(),
            ["api", "seren-agent", "seren-publishers", "seren-db"]
        );
        for skill in list.skills {
            assert_eq!(catalog.skill(&skill.uri).await.unwrap().skill, skill);
            let SkillResources::Files(resources) = skill.resources else {
                panic!("Expected file manifest");
            };
            for resource in resources {
                let mut contents = catalog.read(&resource.uri).await.unwrap().contents;
                let bytes = match contents.pop().unwrap() {
                    ResourceContents::TextResourceContents { text, .. } => {
                        assert!(!resource.uri.ends_with(".bin"));
                        text.into_bytes()
                    }
                    ResourceContents::BlobResourceContents { blob, .. } => {
                        STANDARD.decode(blob).unwrap()
                    }
                    _ => panic!("Unexpected skill resource contents"),
                };
                resource.verify(&bytes).unwrap();
            }
        }
        assert!(catalog.read("skill://seren/api/../unknown").await.is_err());
        server.verify().await;
    }

    #[tokio::test]
    async fn rejects_unofficial_ownership_and_backs_off_after_a_failed_fetch() {
        let server = MockServer::start().await;
        let catalog = Catalog::new(&server.uri()).unwrap();
        mock_catalog(&server, Uuid::nil()).await;
        assert!(catalog.list().await.is_err());
        assert!(catalog.list().await.is_err());
        server.verify().await;
    }
}
