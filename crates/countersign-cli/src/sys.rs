//! Small lookups in system files: users, groups, `/proc`.

use std::fs;

/// The uid of `name` in `/etc/passwd`.
pub fn user_uid(name: &str) -> Option<u32> {
    passwd_field(&fs::read_to_string("/etc/passwd").ok()?, name, 2)
}

/// The gid and member list of group `name` in `/etc/group`.
pub fn group(name: &str) -> Option<(u32, Vec<String>)> {
    let text = fs::read_to_string("/etc/group").ok()?;
    parse_group(&text, name)
}

/// The login name for `uid` in `/etc/passwd`.
pub fn user_name(uid: u32) -> Option<String> {
    let text = fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|line| {
        let mut f = line.split(':');
        let name = f.next()?;
        let id: u32 = f.nth(1)?.parse().ok()?;
        (id == uid).then(|| name.to_owned())
    })
}

fn passwd_field(text: &str, name: &str, index: usize) -> Option<u32> {
    text.lines().find_map(|line| {
        let mut f = line.split(':');
        (f.next()? == name).then_some(())?;
        f.nth(index - 1)?.parse().ok()
    })
}

fn parse_group(text: &str, name: &str) -> Option<(u32, Vec<String>)> {
    text.lines().find_map(|line| {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 4 || f[0] != name {
            return None;
        }
        let gid = f[2].parse().ok()?;
        let members = f[3]
            .split(',')
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .collect();
        Some((gid, members))
    })
}

/// `TracerPid` from `/proc/self/status`.
pub fn tracer_pid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("TracerPid:"))
        .and_then(|v| v.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_passwd_and_group_lines() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      countersign:x:478:478:countersign secret daemon:/var/lib/countersign:/usr/sbin/nologin\n";
        assert_eq!(passwd_field(passwd, "countersign", 2), Some(478));
        assert_eq!(passwd_field(passwd, "root", 2), Some(0));
        assert_eq!(passwd_field(passwd, "nobody", 2), None);

        let group = "wheel:x:10:\ncountersign-users:x:477:patrick,ci\n";
        assert_eq!(
            parse_group(group, "countersign-users"),
            Some((477, vec!["patrick".into(), "ci".into()]))
        );
        assert_eq!(parse_group(group, "wheel"), Some((10, vec![])));
        assert_eq!(parse_group(group, "missing"), None);
    }
}
