//! Shared integer-only JSON/TOON codec, re-exported from [`fa_model::json`].
//!
//! Keeping this surface preserves the CLI, daemon and MCP API while formats
//! use the same pure decoder through the lower model layer.

pub use fa_model::json::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_floats() {
        let v = parse(r#"{"b":[1,-2,"x\"y\n",true,null],"a":{"k":"é"}}"#).unwrap();
        assert_eq!(
            v.render(),
            r#"{"a":{"k":"é"},"b":[1,-2,"x\"y\n",true,null]}"#
        );
        assert_eq!(parse(&v.render()).unwrap().render(), v.render());
        assert!(
            parse("1.5")
                .unwrap_err()
                .message
                .contains("amounts as strings")
        );
        assert!(parse("1e3").is_err());
        assert!(
            parse(r#"{"a":1,"a":2}"#)
                .unwrap_err()
                .message
                .contains("duplicate")
        );
        assert!(parse("[1,]").is_err());
        assert!(parse("{\"a\":1} x").is_err());
        assert_eq!(parse("\"\\u0041\"").unwrap(), Json::Str("A".into()));
    }

    #[test]
    fn integer_grammar_and_full_i128_domain() {
        for value in [i128::MIN, -10, -1, 0, 1, 10, i128::MAX] {
            assert_eq!(parse(&value.to_string()).unwrap(), Json::Int(value));
        }
        assert_eq!(parse("-0").unwrap(), Json::Int(0));
        for text in [
            "00",
            "01",
            "-00",
            "-01",
            "-",
            "- 1",
            "+1",
            "1.0",
            "1e0",
            "1E+3",
            "170141183460469231731687303715884105728",
            "-170141183460469231731687303715884105729",
        ] {
            assert!(parse(text).is_err(), "accepted {text:?}");
            assert!(
                parse(&format!("[{text}]")).is_err(),
                "accepted array {text:?}"
            );
        }
    }

    #[test]
    fn rejects_all_unescaped_controls_but_round_trips_escaped_controls() {
        for code in 0_u8..0x20 {
            let text = format!("\"{}\"", char::from(code));
            assert!(parse(&text).is_err(), "accepted raw control {code}");
            let escaped = format!(r#""\u{code:04x}""#);
            let value = Json::Str(char::from(code).to_string());
            assert_eq!(parse(&escaped).unwrap(), value);
            assert_eq!(parse(&value.render()).unwrap(), value);
        }
    }

    #[test]
    fn surrogate_pairs_preserve_non_bmp_identifiers() {
        for (text, expected) in [
            (r#""\uD834\uDD1E""#, "\u{1d11e}"),
            (r#""\ud83d\ude00""#, "\u{1f600}"),
            (r#""\uD800\uDC00""#, "\u{10000}"),
            (r#""\uDBFF\uDFFF""#, "\u{10ffff}"),
            (r#""\uFFFD""#, "\u{fffd}"),
        ] {
            let value = parse(text).unwrap();
            assert_eq!(value, Json::Str(expected.into()));
            assert_eq!(parse(&value.render()).unwrap(), value);
        }
    }

    #[test]
    fn malformed_unicode_is_never_replaced_or_accepted_as_a_signed_hex_number() {
        for text in [
            r#""\uD800""#,
            r#""\uDC00""#,
            r#""\uDFFF""#,
            r#""\uD800x""#,
            r#""\uD800\n""#,
            r#""\uD800\u0041""#,
            r#""\uD800\uD800""#,
            r#""\uDC00\uD800""#,
            r#""\u+041""#,
            r#""\u-041""#,
            r#""\u 041""#,
            r#""\u00xz""#,
            r#""\u123""#,
            r#""\uD800\u12""#,
        ] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn duplicate_detection_uses_decoded_keys_at_every_object_depth() {
        for text in [
            r#"{"a":1,"\u0061":2}"#,
            r#"{"nested":{"a":1,"\u0061":2}}"#,
            r#"[{"a":1,"\u0061":2}]"#,
            "{\"\u{1f600}\":1,\"\\ud83d\\ude00\":2}",
        ] {
            assert!(parse(text).unwrap_err().message.contains("duplicate"));
        }
        // Reusing a key in a different object is legal.
        assert!(parse(r#"{"a":1,"nested":{"a":2}}"#).is_ok());
    }

    #[test]
    fn raw_and_escaped_identifiers_have_identical_canonical_bytes() {
        let raw = parse("{\"\u{1f600}\":\"\u{1d11e}\",\"a\":1}").unwrap();
        let escaped = parse(r#"{"a":1,"\ud83d\ude00":"\ud834\udd1e"}"#).unwrap();
        assert_eq!(raw.render(), escaped.render());
    }

    #[test]
    fn nesting_limit_and_truncated_tokens_fail_without_panicking() {
        let at_limit = format!("{}0{}", "[".repeat(64), "]".repeat(64));
        assert!(parse(&at_limit).is_ok());
        let too_deep = format!("[{at_limit}]");
        assert!(parse(&too_deep).is_err());
        for text in ["", "[", "{", "\"", "\"\\", "\"\\u", "\"\\uD800\\u", "tru"] {
            assert!(parse(text).is_err(), "accepted {text:?}");
        }
    }

    #[test]
    fn toon_spec_primitives_and_accounting_amounts_golden_vectors() {
        for (input, expected) in [
            (r#""hello""#, "hello"),
            (r#""Ada_99""#, "Ada_99"),
            (r#""""#, r#""""#),
            (r#""true""#, r#""true""#),
            (r#""false""#, r#""false""#),
            (r#""null""#, r#""null""#),
            (r#""42""#, r#""42""#),
            (r#""-3.14""#, r#""-3.14""#),
            (r#""1e-6""#, r#""1e-6""#),
            (r#""05""#, r#""05""#),
            (r#""line1\nline2""#, r#""line1\nline2""#),
            (r#""tab\there""#, r#""tab\there""#),
            (r#""return\rcarriage""#, r#""return\rcarriage""#),
            (r#""C:\\Users\\path""#, r#""C:\\Users\\path""#),
            (r#""[3]: x,y""#, r#""[3]: x,y""#),
            (r#""- item""#, r#""- item""#),
            (r#""[test]""#, r#""[test]""#),
            (r#""{key}""#, r#""{key}""#),
            (r#""café""#, "café"),
            (r#""你好""#, "你好"),
            (r#""🚀""#, "🚀"),
            (r#""hello 👋 world""#, "hello 👋 world"),
            ("42", "42"),
            ("-7", "-7"),
            ("0", "0"),
            ("-0", "0"),
            ("true", "true"),
            ("false", "false"),
            ("null", "null"),
            // Accounting amounts and identifiers stay strings in TOON:
            (r#""1500.00 USD""#, "1500.00 USD"),
            (r#""0.00 USD""#, "0.00 USD"),
            (r#""-42.50 USD""#, r#""-42.50 USD""#),
            (r#""1000""#, r#""1000""#),
            (
                r#""00000000000000000000000000000001""#,
                r#""00000000000000000000000000000001""#,
            ),
        ] {
            let val = parse(input).expect(input);
            assert_eq!(val.render_toon(), expected, "input: {input}");
        }
    }

    #[test]
    fn toon_spec_objects_golden_vectors() {
        for (input, expected) in [
            (
                r#"{"id":123,"name":"Ada","active":true}"#,
                "id: 123\nname: Ada\nactive: true",
            ),
            (r#"{"id":123,"value":null}"#, "id: 123\nvalue: null"),
            (r#"{}"#, ""),
            (r#"{"note":"a:b"}"#, r#"note: "a:b""#),
            (r#"{"note":"a,b"}"#, r#"note: "a,b""#),
            (r#"{"text":"line1\nline2"}"#, r#"text: "line1\nline2""#),
            (r#"{"text":"say \"hello\""}"#, r#"text: "say \"hello\"""#),
            (r#"{"text":" padded "}"#, r#"text: " padded ""#),
            (r#"{"text":"  "}"#, r#"text: "  ""#),
            (r#"{"v":"true"}"#, r#"v: "true""#),
            (r#"{"v":"42"}"#, r#"v: "42""#),
            (r#"{"v":"-7.5"}"#, r#"v: "-7.5""#),
            (r#"{"order:id":7}"#, r#""order:id": 7"#),
            (r#"{"[index]":5}"#, r#""[index]": 5"#),
            (r#"{"-lead":1}"#, r#""-lead": 1"#),
            (r#"{"123":1}"#, r#""123": 1"#),
            (r#"{"":1}"#, r#""": 1"#),
            (
                r#"{"user_name":1,"_id":2,"a.b":3}"#,
                "user_name: 1\n_id: 2\na.b: 3",
            ),
            (r#"{"a":{"b":{"c":"deep"}}}"#, "a:\n  b:\n    c: deep"),
            (r#"{"user":{}}"#, "user:"),
        ] {
            let val = parse(input).expect(input);
            assert_eq!(val.render_toon(), expected, "input: {input}");
        }
    }

    #[test]
    fn toon_spec_arrays_primitive_tabular_nested_and_objects_golden_vectors() {
        for (input, expected) in [
            // arrays-primitive.json
            (
                r#"{"tags":["reading","gaming"]}"#,
                "tags[2]: reading,gaming",
            ),
            (r#"{"nums":[1,2,3]}"#, "nums[3]: 1,2,3"),
            (r#"{"data":["x","y",true,10]}"#, "data[4]: x,y,true,10"),
            (r#"{"items":[]}"#, "items[0]:"),
            (r#"{"items":[""]}"#, r#"items[1]: """#),
            (r#"{"items":["a","","b"]}"#, r#"items[3]: a,"",b"#),
            (r#"{"items":[" ","  "]}"#, r#"items[2]: " ","  ""#),
            (
                r#"{"items":["a","b,c","d:e"]}"#,
                r#"items[3]: a,"b,c","d:e""#,
            ),
            (
                r#"{"items":["x","true","42","-3.14"]}"#,
                r#"items[4]: x,"true","42","-3.14""#,
            ),
            (
                r#"{"items":["[5]","- item","{key}"]}"#,
                r#"items[3]: "[5]","- item","{key}""#,
            ),
            // arrays-tabular.json
            (
                r#"{"items":[{"sku":"A1","qty":2,"price":"9.99 USD"},{"sku":"B2","qty":1,"price":"14.50 USD"}]}"#,
                "items[2]{sku,qty,price}:\n  A1,2,9.99 USD\n  B2,1,14.50 USD",
            ),
            (
                r#"{"items":[{"id":1,"value":null},{"id":2,"value":"test"}]}"#,
                "items[2]{id,value}:\n  1,null\n  2,test",
            ),
            (
                r#"{"items":[{"sku":"A,1","desc":"cool","qty":2},{"sku":"B2","desc":"wip: test","qty":1}]}"#,
                "items[2]{sku,desc,qty}:\n  \"A,1\",cool,2\n  B2,\"wip: test\",1",
            ),
            (
                r#"{"items":[{"id":1,"status":"true"},{"id":2,"status":"false"}]}"#,
                "items[2]{id,status}:\n  1,\"true\"\n  2,\"false\"",
            ),
            (
                r#"{"items":[{"order:id":1,"full name":"Ada"},{"order:id":2,"full name":"Bob"}]}"#,
                "items[2]{\"order:id\",\"full name\"}:\n  1,Ada\n  2,Bob",
            ),
            (
                r#"{"items":[{"a":1,"b":2,"c":3},{"c":30,"b":20,"a":10}]}"#,
                "items[2]{a,b,c}:\n  1,2,3\n  10,20,30",
            ),
            // arrays-nested.json
            (
                r#"{"pairs":[["a","b"],["c","d"]]}"#,
                "pairs[2]:\n  - [2]: a,b\n  - [2]: c,d",
            ),
            (
                r#"{"pairs":[["a","b"],["c,d","e:f","true"]]}"#,
                "pairs[2]:\n  - [2]: a,b\n  - [3]: \"c,d\",\"e:f\",\"true\"",
            ),
            (r#"{"pairs":[[],[]]}"#, "pairs[2]:\n  - [0]:\n  - [0]:"),
            (
                r#"{"pairs":[[1],[2,3]]}"#,
                "pairs[2]:\n  - [1]: 1\n  - [2]: 2,3",
            ),
            (r#"["x","y","true",true,10]"#, r#"[5]: x,y,"true",true,10"#),
            (r#"[{"id":1},{"id":2}]"#, "[2]{id}:\n  1\n  2"),
            (
                r#"[{"id":1},{"id":2,"name":"Ada"}]"#,
                "[2]:\n  - id: 1\n  - id: 2\n    name: Ada",
            ),
            (
                r#"["summary",{"id":1,"name":"Ada"},[{"id":2},{"status":"draft"}]]"#,
                "[3]:\n  - summary\n  - id: 1\n    name: Ada\n  - [2]:\n    - id: 2\n    - status: draft",
            ),
            (r#"[[1,2],[]]"#, "[2]:\n  - [2]: 1,2\n  - [0]:"),
            (r#"[]"#, "[0]:"),
            (
                r#"{"user":{"id":123,"name":"Ada","tags":["reading","gaming"],"active":true,"prefs":[]}}"#,
                "user:\n  id: 123\n  name: Ada\n  tags[2]: reading,gaming\n  active: true\n  prefs[0]:",
            ),
            (
                r#"{"items":[1,{"a":1},"text"]}"#,
                "items[3]:\n  - 1\n  - a: 1\n  - text",
            ),
            (
                r#"{"items":[{"a":1},[1,2]]}"#,
                "items[2]:\n  - a: 1\n  - [2]: 1,2",
            ),
            // arrays-objects.json
            (
                r#"{"items":[{"id":1,"name":"First"},{"id":2,"name":"Second","extra":true}]}"#,
                "items[2]:\n  - id: 1\n    name: First\n  - id: 2\n    name: Second\n    extra: true",
            ),
            (
                r#"{"items":[{"id":1,"nested":{"x":1}}]}"#,
                "items[1]:\n  - id: 1\n    nested:\n      x: 1",
            ),
            (
                r#"{"items":[{"nums":[1,2,3],"name":"Ada"}]}"#,
                "items[1]:\n  - nums[3]: 1,2,3\n    name: Ada",
            ),
            (
                r#"{"items":[{"name":"Ada","nums":[1,2,3]}]}"#,
                "items[1]:\n  - name: Ada\n    nums[3]: 1,2,3",
            ),
            (
                r#"{"items":[{"matrix":[[1,2],[3,4]],"name":"grid"}]}"#,
                "items[1]:\n  - matrix[2]:\n      - [2]: 1,2\n      - [2]: 3,4\n    name: grid",
            ),
            (
                r#"{"items":[{"users":[{"id":1,"name":"Ada"},{"id":2,"name":"Bob"}],"status":"active"}]}"#,
                "items[1]:\n  - users[2]{id,name}:\n      1,Ada\n      2,Bob\n    status: active",
            ),
            (
                r#"{"items":[{"users":[{"id":1,"name":"Ada"},{"id":2}],"status":"active"}]}"#,
                "items[1]:\n  - users[2]:\n      - id: 1\n        name: Ada\n      - id: 2\n    status: active",
            ),
            (
                r#"{"items":[{"nums":[1,2],"tags":["a","b"],"name":"test"}]}"#,
                "items[1]:\n  - nums[2]: 1,2\n    tags[2]: a,b\n    name: test",
            ),
            (
                r#"{"items":[{"nums":[1,2,3],"tags":["a","b"]}]}"#,
                "items[1]:\n  - nums[3]: 1,2,3\n    tags[2]: a,b",
            ),
            (
                r#"{"items":[{"name":"Ada","data":[]}]}"#,
                "items[1]:\n  - name: Ada\n    data[0]:",
            ),
            (
                r#"{"items":[{"users":[{"id":1},{"id":2}],"note":"x"}]}"#,
                "items[1]:\n  - users[2]{id}:\n      1\n      2\n    note: x",
            ),
            (
                r#"{"items":[{"users":[{"id":1,"name":"Ada"},{"id":2,"name":"Bob"}]}]}"#,
                "items[1]:\n  - users[2]{id,name}:\n      1,Ada\n      2,Bob",
            ),
            (
                r#"{"items":[{"data":[],"name":"x"}]}"#,
                "items[1]:\n  - data[0]:\n    name: x",
            ),
            (
                r#"{"items":["first","second",{}]}"#,
                "items[3]:\n  - first\n  - second\n  -",
            ),
            (
                r#"{"items":[{"id":1,"data":"string"},{"id":2,"data":{"nested":true}}]}"#,
                "items[2]:\n  - id: 1\n    data: string\n  - id: 2\n    data:\n      nested: true",
            ),
        ] {
            let val = parse(input).expect(input);
            let encoded = val.render_toon();
            assert_eq!(encoded, expected, "input: {input}");
            assert!(!encoded.ends_with('\n'), "no trailing newline: {input}");
            for line in encoded.lines() {
                assert!(!line.ends_with(' '), "no trailing space on line {line:?}");
            }
        }
    }
}
