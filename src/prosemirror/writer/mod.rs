//! Markdown → ProseMirror JSON. The event-walking `DocBuilder` impl lives in [`build`].

mod build;

use pulldown_cmark::{Options, Parser};
use serde_json::Value;

use super::nodes::Frame;

/// Convert a Markdown string into a Docmost ProseMirror document
/// (`{ "type": "doc", "content": [...] }`).
///
/// This is the inverse of [`super::prosemirror_to_markdown`]. It emits the same node and
/// mark `type` strings (and attr keys) the reader recognizes — note the Tiptap-style mark
/// names `bold`/`italic` (not `strong`/`em`) — so the two round-trip.
///
/// This is the conservative form, for contexts without page-only nodes: it behaves as
/// [`WriteContext::Comment`]. Use [`markdown_to_prosemirror_in`] with
/// [`WriteContext::Page`] for page bodies.
///
/// Mentions use a link-style convention: `[Label](user:UUID)` becomes a user mention and
/// `[Label](page:UUID)` a page mention (any other link URL stays an ordinary link).
pub fn markdown_to_prosemirror(content: &str) -> Value {
    markdown_to_prosemirror_in(content, WriteContext::Comment)
}

/// Where converted Markdown will be stored, which decides which nodes it may produce.
///
/// Docmost's page editor and its comment editor have different schemas. The comment editor
/// (`comment-editor.tsx`: StarterKit, link, emoji, mention) has no `embed` node, so content
/// containing one cannot be rendered there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteContext {
    /// A page body. A bare link — one whose text is its URL, such as `[url](url)` or
    /// `<url>` — to a provider Docmost embeds (YouTube, Vimeo, Loom, ...) becomes a block
    /// `embed` node, as it does through Docmost's own Markdown import. The reader renders
    /// an embed in that form.
    Page,
    /// A comment body. Only nodes the comment editor has are produced; a bare video link
    /// stays an ordinary link, with its URL intact.
    Comment,
}

/// [`markdown_to_prosemirror`] for an explicit [`WriteContext`].
pub fn markdown_to_prosemirror_in(content: &str, context: WriteContext) -> Value {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TASKLISTS);

    let mut builder = DocBuilder::new(context);
    for event in Parser::new_ext(content, options) {
        builder.handle(event);
    }
    builder.finish()
}

struct ImageState {
    src: String,
    alt: String,
}

/// A pending mention captured between a `[label](user:ID)` link's start and end events.
struct Mention {
    entity_type: String,
    entity_id: String,
    label: String,
}

/// An open link in a paragraph: its URL and where its text starts in the paragraph's
/// content, so a bare provider link can be swapped for an `embed` when it closes.
struct PendingLink {
    href: String,
    start: usize,
}

struct DocBuilder {
    context: WriteContext,
    stack: Vec<Frame>,
    marks: Vec<Value>,
    in_table_head: bool,
    image: Option<ImageState>,
    pending_mention: Option<Mention>,
    pending_link: Option<PendingLink>,
}
