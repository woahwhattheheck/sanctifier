#![allow(deprecated)]

use assert_cmd::Command;
use std::env;
use std::fs;

fn json_type_matches(expected: &str, value: &serde_json::Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    }
}

fn assert_schema_matches(schema: &serde_json::Value, value: &serde_json::Value, path: &str) {
    if let Some(expected) = schema.get("const") {
        assert_eq!(value, expected, "{path} does not match schema const");
    }

    if let Some(expected_type) = schema.get("type").and_then(serde_json::Value::as_str) {
        assert!(
            json_type_matches(expected_type, value),
            "{path} expected JSON type {expected_type}, got {value}"
        );
    }

    if let Some(object) = value.as_object() {
        let properties = schema
            .get("properties")
            .and_then(serde_json::Value::as_object);

        if let Some(required) = schema.get("required").and_then(serde_json::Value::as_array) {
            for key in required.iter().filter_map(serde_json::Value::as_str) {
                assert!(
                    object.contains_key(key),
                    "{path} missing required property {key}"
                );
            }
        }

        if let Some(properties) = properties {
            for (key, child_schema) in properties {
                if let Some(child_value) = object.get(key) {
                    let child_path = format!("{path}.{key}");
                    assert_schema_matches(child_schema, child_value, &child_path);
                }
            }

            if schema
                .get("additionalProperties")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
            {
                for key in object.keys() {
                    assert!(
                        properties.contains_key(key),
                        "{path} has undocumented property {key}"
                    );
                }
            }
        }
    }

    if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
        for (index, item) in array.iter().enumerate() {
            let item_path = format!("{path}[{index}]");
            assert_schema_matches(items, item, &item_path);
        }
    }
}

#[test]
fn analyze_json_matches_published_v1_schema() {
    let fixture_path = env::current_dir()
        .unwrap()
        .join("tests/fixtures/valid_contract.rs");

    let output = Command::cargo_bin("sanctifier")
        .unwrap()
        .arg("analyze")
        .arg(fixture_path)
        .arg("--format")
        .arg("json")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "sanctifier analyze failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/sanctifier-ci-v1.schema.json");
    let schema_text = fs::read_to_string(&schema_path).unwrap();
    let schema: serde_json::Value = serde_json::from_str(&schema_text).unwrap();

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(
        schema["$id"],
        "https://github.com/Centurylong/sanctifier/blob/main/schemas/sanctifier-ci-v1.schema.json"
    );
    assert_schema_matches(&schema, &report, "$");
}
