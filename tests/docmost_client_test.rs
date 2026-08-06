use docmost_mcp::docmost_client::{
    CursorListResult, ListResult, PaginationMeta, into_page, normalize_list_result,
};

fn cursor_result<T>(items: Option<Vec<T>>) -> CursorListResult<T> {
    CursorListResult {
        items,
        meta: None,
        next_cursor: None,
        has_next_page: None,
        total: None,
    }
}

#[test]
fn returns_array_results_unchanged() {
    assert_eq!(
        normalize_list_result(Some(ListResult::List(vec![1, 2]))),
        vec![1, 2]
    );
}

#[test]
fn extracts_items_arrays_from_wrapped_responses() {
    assert_eq!(
        normalize_list_result(Some(ListResult::Wrapped {
            items: Some(vec![1]),
        })),
        vec![1]
    );
}

#[test]
fn returns_empty_array_for_null_or_empty_item_collections() {
    assert_eq!(normalize_list_result::<i32>(None), Vec::<i32>::new());
    assert_eq!(
        normalize_list_result(Some(ListResult::<i32>::Wrapped { items: None })),
        Vec::<i32>::new()
    );
}

#[test]
fn extracts_items_from_cursor_paginated_responses() {
    let page = into_page(cursor_result(Some(vec![1, 2, 3])));
    assert_eq!(page.items, vec![1, 2, 3]);
}

#[test]
fn returns_empty_array_for_missing_cursor_paginated_items() {
    let page = into_page(cursor_result::<i32>(None));
    assert_eq!(page.items, Vec::<i32>::new());
    assert!(page.is_empty());
}

#[test]
fn reads_pagination_metadata_from_nested_meta() {
    // Docmost's nested envelope: { items, meta: { nextCursor, hasNextPage, total } }
    let page = into_page(CursorListResult {
        items: Some(vec![1, 2]),
        meta: Some(PaginationMeta {
            next_cursor: Some("cur-2".to_string()),
            has_next_page: Some(true),
            total: Some(57),
            ..Default::default()
        }),
        next_cursor: None,
        has_next_page: None,
        total: None,
    });
    assert_eq!(page.next_cursor.as_deref(), Some("cur-2"));
    assert_eq!(page.has_more, Some(true));
    assert_eq!(page.total, Some(57));
}

#[test]
fn reads_pagination_metadata_from_flat_shape() {
    // The other shape Docmost has shipped: { items, nextCursor } with no `meta`.
    let page = into_page(CursorListResult {
        items: Some(vec![1]),
        meta: None,
        next_cursor: Some("cur-9".to_string()),
        has_next_page: None,
        total: Some(3),
    });
    assert_eq!(page.next_cursor.as_deref(), Some("cur-9"));
    assert_eq!(page.total, Some(3));
    // A cursor implies there is more, even when hasNextPage was not sent.
    assert_eq!(page.has_more, Some(true));
}

#[test]
fn nested_meta_wins_over_flat_fields() {
    let page = into_page(CursorListResult {
        items: Some(vec![1]),
        meta: Some(PaginationMeta {
            next_cursor: Some("from-meta".to_string()),
            ..Default::default()
        }),
        next_cursor: Some("from-flat".to_string()),
        has_next_page: None,
        total: None,
    });
    assert_eq!(page.next_cursor.as_deref(), Some("from-meta"));
}

#[test]
fn has_more_is_unknown_when_the_server_says_nothing() {
    // Must NOT be inferred from items.len() == limit: a final page that happens to
    // be exactly full would then be reported as having more, and an agent would
    // page forever. Unknown is reported as unknown.
    let page = into_page(cursor_result(Some(vec![1, 2, 3])));
    assert_eq!(page.has_more, None);
    assert!(page.next_cursor.is_none());
}

#[test]
fn explicit_no_next_page_is_preserved() {
    let page = into_page(CursorListResult {
        items: Some(vec![1]),
        meta: Some(PaginationMeta {
            has_next_page: Some(false),
            ..Default::default()
        }),
        next_cursor: None,
        has_next_page: None,
        total: None,
    });
    assert_eq!(page.has_more, Some(false));
}

#[test]
fn json_mode_preserves_fields_this_server_does_not_model() {
    // The `response_format: "json"` contract promises complete records. Serde drops
    // unknown keys by default, so before this the promise was false: fields Docmost
    // added after these structs were written (createdAt, workspaceId, isLocked,
    // contributors, permissions, ...) vanished silently.
    use docmost_mcp::types::DocmostPage;

    let raw = serde_json::json!({
        "id": "p1",
        "slugId": "abc",
        "title": "Roadmap",
        "createdAt": "2026-08-06T00:00:00Z",
        "workspaceId": "ws-1",
        "isLocked": false,
        "contributors": ["u1", "u2"],
        "permissions": { "edit": true }
    });

    let page: DocmostPage = serde_json::from_value(raw.clone()).expect("parses");
    let back = serde_json::to_value(&page).expect("serializes");

    // Modelled fields survive.
    assert_eq!(back["id"], "p1");
    assert_eq!(back["title"], "Roadmap");
    // Unmodelled fields survive too — flattened back to the top level, not nested.
    assert_eq!(back["createdAt"], "2026-08-06T00:00:00Z");
    assert_eq!(back["workspaceId"], "ws-1");
    assert_eq!(back["isLocked"], false);
    assert_eq!(back["contributors"], serde_json::json!(["u1", "u2"]));
    assert_eq!(back["permissions"]["edit"], true);
}

#[test]
fn unmodelled_fields_are_not_nested_under_extra() {
    // They must round-trip at the top level. If they surfaced as {"extra": {...}}
    // the JSON shape would differ from the API's and callers would break.
    use docmost_mcp::types::DocmostSpace;

    let raw = serde_json::json!({ "id": "s1", "slug": "eng", "somethingNew": 42 });
    let space: DocmostSpace = serde_json::from_value(raw).expect("parses");
    let back = serde_json::to_value(&space).expect("serializes");

    assert_eq!(back["somethingNew"], 42);
    assert!(back.get("extra").is_none(), "must not nest: {back}");
}
