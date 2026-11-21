//! Lightweight UTC and local time helpers backed by `std::time` and `libc`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current wall-clock timestamp in Unix seconds.
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Formats a Unix timestamp in local time as `YYYY-MM-DD HH:MM:SS`.
pub fn format_local_datetime(unix_secs: i64) -> String {
    if unix_secs <= 0 {
        return String::new();
    }
    let t = unix_secs as _;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::localtime_r(&t, &mut tm) };
    if res.is_null() {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// Formats a Unix timestamp in local time as `YYYYMMDD`.
pub fn format_local_yyyymmdd(unix_secs: i64) -> String {
    if unix_secs <= 0 {
        return String::new();
    }
    let t = unix_secs as _;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::localtime_r(&t, &mut tm) };
    if res.is_null() {
        return String::new();
    }
    format!(
        "{:04}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday
    )
}

/// Formats a Unix timestamp in UTC as `YYYY-MM-DD HH:MM:SS`.
pub fn format_utc_datetime(unix_secs: i64) -> String {
    if unix_secs < 0 {
        return String::new();
    }
    let t = unix_secs as _;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::gmtime_r(&t, &mut tm) };
    if res.is_null() {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// Formats a Unix timestamp in UTC as `YYYY-MM-DD`.
pub fn format_utc_date(unix_secs: i64) -> String {
    if unix_secs < 0 {
        return String::new();
    }
    let t = unix_secs as _;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::gmtime_r(&t, &mut tm) };
    if res.is_null() {
        return String::new();
    }
    format!(
        "{:04}-{:02}-{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday
    )
}

/// Formats a Unix timestamp in local time as ISO-8601 `YYYY-MM-DDTHH:MM:SS+HHMM`.
pub fn format_local_iso8601(unix_secs: i64) -> String {
    if unix_secs <= 0 {
        return String::new();
    }
    let t = unix_secs as _;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::localtime_r(&t, &mut tm) };
    if res.is_null() {
        return String::new();
    }
    let off = tm.tm_gmtoff as i64;
    let sign = if off >= 0 { '+' } else { '-' };
    let abs_off = off.abs();
    let oh = abs_off / 3600;
    let om = (abs_off % 3600) / 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        sign,
        oh,
        om
    )
}

/// Converts broken-down date/time parts with an explicit timezone offset (in seconds
/// east of UTC) to a Unix timestamp using `libc::timegm`.
pub fn parts_to_unix_secs(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    min: u32,
    sec: u32,
    tz_offset_secs: i64,
) -> Option<i64> {
    if !(1970..=2100).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = (month - 1) as libc::c_int;
    tm.tm_mday = day as libc::c_int;
    tm.tm_hour = hour as libc::c_int;
    tm.tm_min = min as libc::c_int;
    tm.tm_sec = sec as libc::c_int;
    let utc = unsafe { libc::timegm(&mut tm) };
    if utc == -1 {
        return None;
    }
    Some((utc as i64) - tz_offset_secs)
}
