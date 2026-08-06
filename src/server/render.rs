use once_cell::sync::Lazy;
use regex::Regex;

use crate::docmost_client::Page;
use crate::types::{
    DocmostComment, DocmostCurrentUserResponse, DocmostPage, DocmostPageListItem,
    DocmostSearchResult, DocmostUser,
};

static HIGHLIGHT_TAGS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"<[^>]+>").expect("valid highlight strip regex"));
static COLLAPSE_WHITESPACE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\s+").expect("valid whitespace collapse regex"));

pub fn sanitize_highlight(value: Option<&str>) -> String {
    let Some(value) = value else {
        return String::new();
    };
    COLLAPSE_WHITESPACE_RE
        .replace_all(&HIGHLIGHT_TAGS_RE.replace_all(value, ""), " ")
        .trim()
        .to_string()
}

pub fn format_search_results(query: &str, results: &[DocmostSearchResult]) -> String {
    if results.is_empty() {
        return format!("No Docmost results were found for \"{query}\".");
    }

    let mut lines = vec![format!("## Search Results for \"{query}\""), String::new()];
    let total_results = results.len();

    for (index, result) in results.iter().take(5).enumerate() {
        let space_name = result
            .space
            .as_ref()
            .and_then(|space| space.name.as_deref())
            .unwrap_or("Unknown");
        let preview = sanitize_highlight(result.highlight.as_deref());
        let icon = result.icon.as_deref().unwrap_or("");
        let title = result.title.as_deref().unwrap_or("Untitled");

        if icon.is_empty() {
            lines.push(format!("### {}. {}", index + 1, title));
        } else {
            lines.push(format!("### {}. {} {}", index + 1, icon, title));
        }
        lines.push(format!("- Space: {space_name}"));
        lines.push(format!(
            "- Page ID: {}",
            format_optional_id(result.id.as_deref())
        ));
        lines.push(format!("- Slug ID: `{}`", result.slug_id));
        if !preview.is_empty() {
            lines.push(format!("- Preview: {preview}"));
        }
        lines.push(String::new());
    }

    lines.push(format!(
        "Showing {} of {} results.",
        results.iter().take(5).count(),
        total_results
    ));
    lines.push("Use `docmost_get_page` with a slug ID to retrieve the full page.".to_string());
    lines.join("\n")
}

/// JSON body for a paginated list.
///
/// The Markdown renderers deliberately truncate and summarise; this returns the
/// complete records plus an explicit `pagination` block, so a caller that
/// post-processes results gets the cursor as data rather than having to parse it
/// out of a prose footer.
pub fn page_to_json<T: serde::Serialize>(page: &Page<T>) -> serde_json::Value {
    serde_json::json!({
        "items": page.items,
        "count": page.items.len(),
        "pagination": {
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
            "total": page.total,
        }
    })
}

/// JSON body for a non-paginated list (search results, spaces).
pub fn list_to_json<T: serde::Serialize>(items: &[T]) -> serde_json::Value {
    serde_json::json!({ "items": items, "count": items.len() })
}

/// How many items these renderers show before truncating.
const DISPLAY_CAP: usize = 10;
/// Members render wider rows, so this list shows more before truncating.
const MEMBER_DISPLAY_CAP: usize = 20;

/// Footer telling the agent exactly what it has and how to get the rest.
///
/// Two things were previously invisible to a caller. The renderers cap output at
/// [`DISPLAY_CAP`], so an agent could believe it had seen everything when it had
/// not; and the next cursor was discarded entirely, which made the `cursor`
/// parameter unusable — you could only page forward if you already knew the cursor.
///
/// `has_more` is reported as unknown when the server said nothing, rather than
/// guessed from a full page, so an agent never pages forever off a bad inference.
pub fn format_pagination<T>(page: &Page<T>, shown: usize, cap: usize, noun: &str) -> String {
    let mut parts = Vec::new();
    if shown < page.len() {
        parts.push(format!(
            "Showing {shown} of {} fetched {noun} (display cap {cap})",
            page.len()
        ));
    } else {
        parts.push(format!("Showing {shown} {noun}"));
    }
    if let Some(total) = page.total {
        parts.push(format!("{total} total"));
    }
    match (page.has_more, page.next_cursor.as_deref()) {
        (Some(true), Some(cursor)) => {
            parts.push(format!(
                "more available — pass cursor `{cursor}` to continue"
            ));
        }
        (Some(true), None) => parts.push("more available".to_string()),
        (Some(false), _) => parts.push("end of results".to_string()),
        (None, Some(cursor)) => parts.push(format!("pass cursor `{cursor}` to continue")),
        (None, None) => {}
    }
    parts.join(" · ")
}

pub fn format_page_list(title: &str, scope: &str, pages: &Page<DocmostPageListItem>) -> String {
    if pages.is_empty() {
        return format!("No Docmost pages were found for {scope}.");
    }

    let mut lines = vec![format!("## {title}"), String::new()];
    for (index, page) in pages.items.iter().take(DISPLAY_CAP).enumerate() {
        let icon = page.icon.as_deref().unwrap_or("");
        let title = page.title.as_deref().unwrap_or("Untitled");
        if icon.is_empty() {
            lines.push(format!("### {}. {}", index + 1, title));
        } else {
            lines.push(format!("### {}. {} {}", index + 1, icon, title));
        }
        lines.push(format!("- Page ID: `{}`", page.id));
        lines.push(format!("- Slug ID: `{}`", page.slug_id));
        lines.push(format!(
            "- Parent Page ID: {}",
            format_optional_id(page.parent_page_id.as_deref())
        ));
        lines.push(format!(
            "- Has Children: {}",
            page.has_children.unwrap_or(false)
        ));
        lines.push(String::new());
    }
    lines.push(format_pagination(
        pages,
        pages.items.iter().take(DISPLAY_CAP).count(),
        DISPLAY_CAP,
        "pages",
    ));
    lines.join("\n")
}

pub fn format_comments(page_id: &str, comments: &Page<DocmostComment>) -> String {
    if comments.is_empty() {
        return format!("No comments were found for page `{page_id}`.");
    }

    let mut lines = vec![format!("## Comments for Page `{page_id}`"), String::new()];
    for (index, comment) in comments.items.iter().take(DISPLAY_CAP).enumerate() {
        let author = comment
            .creator
            .as_ref()
            .and_then(|user| user.name.as_deref())
            .unwrap_or("Unknown");
        lines.push(format!("### {}. Comment `{}`", index + 1, comment.id));
        lines.push(format!("- Author: {author}"));
        lines.push(format!(
            "- Parent Comment ID: {}",
            format_optional_id(comment.parent_comment_id.as_deref())
        ));
        lines.push(format!(
            "- Selection: {}",
            comment.selection.as_deref().unwrap_or("None")
        ));
        lines.push(format!(
            "- Resolved: {}",
            if comment.resolved_at.is_some() {
                "Yes"
            } else {
                "No"
            }
        ));
        lines.push(String::new());
    }
    lines.push(format_pagination(
        comments,
        comments.items.iter().take(DISPLAY_CAP).count(),
        DISPLAY_CAP,
        "comments",
    ));
    lines.join("\n")
}

pub fn format_workspace_members(members: &Page<DocmostUser>) -> String {
    if members.is_empty() {
        return "No Docmost workspace members were found.".to_string();
    }

    let mut lines = vec![
        "## Workspace Members".to_string(),
        String::new(),
        "| Name | Email | Role | ID |".to_string(),
        "| --- | --- | --- | --- |".to_string(),
    ];

    for member in members.items.iter().take(MEMBER_DISPLAY_CAP) {
        lines.push(format!(
            "| {} | {} | {} | {} |",
            member.name.as_deref().unwrap_or("Unknown"),
            member.email.as_deref().unwrap_or("Unknown"),
            member.role.as_deref().unwrap_or("Unknown"),
            member.id
        ));
    }

    lines.push(String::new());
    lines.push(format_pagination(
        members,
        members.items.iter().take(MEMBER_DISPLAY_CAP).count(),
        MEMBER_DISPLAY_CAP,
        "members",
    ));
    lines.join("\n")
}

pub fn format_current_user(response: &DocmostCurrentUserResponse) -> String {
    let lines = [
        "# Current Docmost User".to_string(),
        String::new(),
        format!(
            "Name: {}",
            response.user.name.as_deref().unwrap_or("Unknown")
        ),
        format!("User ID: `{}`", response.user.id),
        format!(
            "Email: {}",
            response.user.email.as_deref().unwrap_or("Unknown")
        ),
        format!(
            "Role: {}",
            response.user.role.as_deref().unwrap_or("Unknown")
        ),
        String::new(),
        "## Workspace".to_string(),
        String::new(),
        format!(
            "Name: {}",
            response.workspace.name.as_deref().unwrap_or("Unknown")
        ),
        format!("Workspace ID: `{}`", response.workspace.id),
        format!(
            "Hostname: {}",
            response.workspace.hostname.as_deref().unwrap_or("Unknown")
        ),
        format!(
            "Member count: {}",
            response
                .workspace
                .member_count
                .map(|count| count.to_string())
                .unwrap_or_else(|| "Unknown".to_string())
        ),
    ];

    lines.join("\n")
}

pub fn format_created_page(page: &DocmostPage, requested_title: &str) -> String {
    let title = page.title.as_deref().unwrap_or(requested_title);
    let lines = [
        format!("Created Docmost page \"{title}\"."),
        String::new(),
        format!("Page ID: {}", format_optional_id(page.id.as_deref())),
        format!("Slug ID: {}", format_optional_id(page.slug_id.as_deref())),
        format!("Space ID: {}", format_optional_id(page.space_id.as_deref())),
    ];
    lines.join("\n")
}

/// Format the update confirmation. `body_note` carries an optional caveat about the body
/// update (e.g. "not applied on this server version"); it is appended only when present,
/// so a title-only update or a fully-applied body update has no misleading note.
pub fn format_updated_page(page: &DocmostPage, body_note: Option<&str>) -> String {
    let title = page.title.as_deref().unwrap_or("Untitled");
    let mut lines = vec![
        format!("Updated Docmost page \"{title}\"."),
        String::new(),
        format!("Page ID: {}", format_optional_id(page.id.as_deref())),
        format!("Slug ID: {}", format_optional_id(page.slug_id.as_deref())),
    ];
    if let Some(note) = body_note {
        lines.push(note.to_string());
    }
    lines.join("\n")
}

pub(super) fn format_optional_id(value: Option<&str>) -> String {
    value
        .map(|value| format!("`{value}`"))
        .unwrap_or_else(|| "Unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn page(value: serde_json::Value) -> DocmostPage {
        serde_json::from_value(value).expect("valid DocmostPage")
    }

    fn sample_page(items: Vec<i32>, next: Option<&str>, more: Option<bool>) -> Page<i32> {
        Page {
            items,
            next_cursor: next.map(str::to_string),
            total: Some(57),
            has_more: more,
        }
    }

    #[test]
    fn page_json_exposes_pagination_as_data() {
        // The Markdown footer states the cursor in prose; a JSON caller must get it
        // as a field rather than having to parse it back out of the text.
        let value = page_to_json(&sample_page(vec![1, 2], Some("cur-2"), Some(true)));
        assert_eq!(value["items"], json!([1, 2]));
        assert_eq!(value["count"], json!(2));
        assert_eq!(value["pagination"]["next_cursor"], json!("cur-2"));
        assert_eq!(value["pagination"]["has_more"], json!(true));
        assert_eq!(value["pagination"]["total"], json!(57));
    }

    #[test]
    fn page_json_reports_unknown_has_more_as_null() {
        // Must serialize as null, not false — "we don't know" and "there is no more"
        // are different answers, and collapsing them would make a caller stop early.
        let value = page_to_json(&sample_page(vec![1], None, None));
        assert!(value["pagination"]["has_more"].is_null());
        assert!(value["pagination"]["next_cursor"].is_null());
    }

    #[test]
    fn list_json_has_items_and_count() {
        let value = list_to_json(&[10, 20, 30]);
        assert_eq!(value["items"], json!([10, 20, 30]));
        assert_eq!(value["count"], json!(3));
    }

    #[test]
    fn markdown_footer_names_the_cursor_to_continue() {
        let out = format_pagination(
            &sample_page(vec![1, 2], Some("cur-9"), Some(true)),
            2,
            10,
            "pages",
        );
        assert!(out.contains("cur-9"), "footer must name the cursor: {out}");
        assert!(
            out.contains("57 total"),
            "footer must state the total: {out}"
        );
    }

    #[test]
    fn markdown_footer_states_end_of_results() {
        let out = format_pagination(&sample_page(vec![1], None, Some(false)), 1, 10, "pages");
        assert!(out.contains("end of results"), "output: {out}");
    }

    #[test]
    fn markdown_footer_flags_the_display_cap() {
        // 25 fetched but only 10 shown — the agent must be told, or it will believe
        // it has seen everything that was fetched.
        let out = format_pagination(
            &sample_page((1..=25).collect(), None, None),
            10,
            10,
            "pages",
        );
        assert!(out.contains("display cap 10"), "output: {out}");
        assert!(out.contains("of 25"), "output: {out}");
    }

    #[test]
    fn format_created_page_uses_returned_title_and_ids() {
        let output = format_created_page(
            &page(json!({
                "id": "p1",
                "slugId": "s1",
                "title": "Release Notes",
                "spaceId": "space-1"
            })),
            "requested title",
        );
        assert!(output.contains("Created Docmost page \"Release Notes\"."));
        assert!(output.contains("Page ID: `p1`"));
        assert!(output.contains("Slug ID: `s1`"));
        assert!(output.contains("Space ID: `space-1`"));
    }

    #[test]
    fn format_created_page_falls_back_to_requested_title() {
        // The import endpoint sometimes returns no title; the caller's title is used.
        let output = format_created_page(&page(json!({ "id": "p1" })), "My Requested Title");
        assert!(
            output.contains("Created Docmost page \"My Requested Title\"."),
            "output: {output}"
        );
    }

    #[test]
    fn format_created_page_marks_missing_ids_unknown() {
        let output = format_created_page(&page(json!({ "title": "T" })), "T");
        assert!(output.contains("Page ID: Unknown"), "output: {output}");
        assert!(output.contains("Slug ID: Unknown"), "output: {output}");
        assert!(output.contains("Space ID: Unknown"), "output: {output}");
    }

    #[test]
    fn format_updated_page_has_no_caveat_when_body_note_absent() {
        // A title-only update (or a fully-applied body update) must NOT carry a spurious
        // "collaborative editor" note.
        let output = format_updated_page(
            &page(json!({ "id": "p1", "slugId": "s1", "title": "Renamed" })),
            None,
        );
        assert!(output.contains("Updated Docmost page \"Renamed\"."));
        assert!(output.contains("Page ID: `p1`"));
        assert!(
            !output.to_lowercase().contains("collaborative editor"),
            "no caveat expected, got: {output}"
        );
    }

    #[test]
    fn format_updated_page_appends_body_note_when_present() {
        let output = format_updated_page(
            &page(json!({ "id": "p1", "title": "Renamed" })),
            Some("Note: the body was NOT changed on this server version."),
        );
        assert!(
            output.contains("the body was NOT changed"),
            "output: {output}"
        );
    }

    #[test]
    fn format_updated_page_falls_back_to_untitled() {
        let output = format_updated_page(&page(json!({ "id": "p1" })), None);
        assert!(
            output.contains("Updated Docmost page \"Untitled\"."),
            "output: {output}"
        );
    }
}
