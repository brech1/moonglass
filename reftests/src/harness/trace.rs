//! `--nocapture` execution trace rendering.

use std::io;

use super::{
    color::{Color, Style},
    worker::CaseRun,
};
use crate::adapters::{Outcome, TraceEvent, TraceStatus};
use crate::inventory::Case;

/// Write the `--nocapture` detail for one executed case.
pub(crate) fn write_no_capture_output(
    case: &Case,
    run: &CaseRun,
    color: Color,
    mut out: impl io::Write,
) -> io::Result<()> {
    writeln!(out, "  elapsed: {}", elapsed_text(run.elapsed_ms))?;

    if let Outcome::Fail(detail) = &run.outcome {
        write_failure_detail(&mut out, detail, color)?;
        writeln!(out, "fixture: {}", case.canonical_root_string())?;
        writeln!(out, "rerun:   {}", rerun_command(&case.display_path()))?;
    }

    write_terminal_trace(&mut out, &run.trace, color)?;
    write_stream(&mut out, case, "stdout", &run.stdout)?;
    write_stream(&mut out, case, "stderr", &run.stderr)?;
    Ok(())
}

fn elapsed_text(elapsed_ms: Option<u64>) -> String {
    elapsed_ms.map_or_else(|| "unknown".to_owned(), |ms| format!("{ms} ms"))
}

fn write_failure_detail(mut out: impl io::Write, detail: &str, color: Color) -> io::Result<()> {
    writeln!(out, "  {}:", color.paint(Style::Fail, "failure"))?;
    if detail.is_empty() {
        writeln!(out, "    <empty failure detail>")?;
        return Ok(());
    }
    for line in detail.lines() {
        writeln!(out, "    {line}")?;
    }
    Ok(())
}

fn rerun_command(case_name: &str) -> String {
    let binary = std::env::current_exe().ok().map_or_else(
        || "reftests".to_owned(),
        |path| shell_quote(&path.display().to_string()),
    );
    format!("{binary} {} --nocapture", shell_quote(case_name))
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
    }

    if value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b':' | b'='))
    {
        return value.to_owned();
    }

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn write_terminal_trace(
    mut out: impl io::Write,
    trace: &[TraceEvent],
    color: Color,
) -> io::Result<()> {
    if trace.is_empty() {
        return Ok(());
    }

    let mut current_step: Option<(usize, String)> = None;
    for event in trace {
        if let Some((index, tag)) = event.scope.step() {
            write_terminal_step_heading(&mut out, &mut current_step, index, tag)?;
            write_terminal_trace_event(&mut out, event, 4, color)?;
        } else {
            write_terminal_trace_event(&mut out, event, 2, color)?;
        }
    }
    Ok(())
}

fn write_terminal_step_heading(
    mut out: impl io::Write,
    current_step: &mut Option<(usize, String)>,
    index: usize,
    tag: &str,
) -> io::Result<()> {
    if !is_current_step(current_step.as_ref(), index, tag) {
        *current_step = Some((index, tag.to_owned()));
        writeln!(out, "  step {index} [{tag}]")?;
    }
    Ok(())
}

fn is_current_step(current_step: Option<&(usize, String)>, index: usize, tag: &str) -> bool {
    current_step
        .is_some_and(|(current_index, current_tag)| *current_index == index && current_tag == tag)
}

fn write_terminal_trace_event(
    mut out: impl io::Write,
    event: &TraceEvent,
    indent: usize,
    color: Color,
) -> io::Result<()> {
    let status = format!("{:<4}", event.status.as_word());
    writeln!(
        out,
        "{:indent$}{} {:<36} {}",
        "",
        color.paint(trace_style(event.status), &status),
        event.label,
        event.detail,
        indent = indent
    )
}

const fn trace_style(status: TraceStatus) -> Style {
    match status {
        TraceStatus::Info => Style::Info,
        TraceStatus::Pass => Style::Pass,
        TraceStatus::Fail => Style::Fail,
    }
}

fn write_stream(
    mut out: impl io::Write,
    case: &Case,
    stream: &str,
    bytes: &[u8],
) -> io::Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    writeln!(out, "---- {} {stream} ----", case.display_path())?;
    write!(out, "{}", String::from_utf8_lossy(bytes))?;
    if !bytes.ends_with(b"\n") {
        writeln!(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::TraceScope;
    use crate::harness::color::Color;
    use crate::testing::GET_HEAD_GENESIS;

    #[test]
    fn no_capture_output_includes_trace_context_for_passing_cases() {
        let case = GET_HEAD_GENESIS.to_case();
        let run = CaseRun {
            outcome: Outcome::Pass,
            stdout: b"stdout line\n".to_vec(),
            stderr: b"stderr line\n".to_vec(),
            elapsed_ms: Some(42),
            trace: vec![TraceEvent {
                scope: TraceScope::StepCheck {
                    index: 0,
                    tag: "Checks".to_owned(),
                },
                label: "head.root".to_owned(),
                status: TraceStatus::Pass,
                detail: "root/slot matched".to_owned(),
            }],
        };

        let mut output = Vec::new();
        write_no_capture_output(&case, &run, Color::always(), &mut output)
            .expect("write trace output");
        let output = String::from_utf8(output).expect("trace output is utf-8");

        assert!(
            !output.contains(
                "---- minimal/gloas/fork_choice/get_head/pyspec_tests/genesis trace ----"
            )
        );
        assert!(output.contains("elapsed: 42 ms"));
        assert!(!output.contains("pid 1234"));
        assert!(!output.contains("rerun:"));
        assert!(!output.contains("trace:"));
        assert!(
            output
                .lines()
                .any(|line| line.contains("ok") && line.contains("head.root"))
        );
        assert!(output.contains("root/slot matched"));
        assert!(output.contains("stdout line"));
        assert!(output.contains("stderr line"));
    }

    #[test]
    fn shell_quote_keeps_simple_case_names_readable() {
        let case = GET_HEAD_GENESIS.to_case();

        assert_eq!(shell_quote(&case.display_path()), case.display_path());
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("case with ' quote"), "'case with '\\'' quote'");
    }

    #[test]
    fn no_capture_output_includes_failure_detail() {
        let case = GET_HEAD_GENESIS.to_case();
        let run = CaseRun {
            outcome: Outcome::Fail("head mismatch\nexpected 0x01".to_owned()),
            stdout: Vec::new(),
            stderr: Vec::new(),
            elapsed_ms: Some(7),
            trace: Vec::new(),
        };

        let mut output = Vec::new();
        write_no_capture_output(&case, &run, Color::always(), &mut output)
            .expect("write trace output");
        let output = String::from_utf8(output).expect("trace output is utf-8");

        assert!(output.contains("failure"));
        assert!(output.contains("head mismatch"));
        assert!(output.contains("expected 0x01"));
        assert!(output.contains("fixture:"));
        assert!(output.contains("rerun:"));
    }
}
