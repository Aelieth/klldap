/// Sort key that floats the well-known user attributes to the top of a form
/// in a fixed order, with everything else after, then alphabetical by name.
pub fn attribute_priority(name: &str) -> (i32, String) {
    const PRIORITIES: [&str; 9] = [
        "firstname",
        "lastname",
        "displayname",
        "mail",
        "avatar",
        "uidnumber",
        "gidnumber",
        "homedirectory",
        "loginshell",
    ];
    let index = PRIORITIES
        .iter()
        .position(|&p| p == name)
        .map(|i| i as i32)
        .unwrap_or(100);
    (index, name.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::attribute_priority;

    #[test]
    fn known_attributes_sort_before_unknown_and_in_order() {
        let mut names = vec!["zebra", "loginshell", "firstname", "mail", "custom_thing"];
        names.sort_by_key(|n| attribute_priority(n));
        assert_eq!(
            names,
            vec!["firstname", "mail", "loginshell", "custom_thing", "zebra"]
        );
    }

    #[test]
    fn unknown_attributes_break_ties_alphabetically() {
        assert!(attribute_priority("apple") < attribute_priority("banana"));
    }
}
