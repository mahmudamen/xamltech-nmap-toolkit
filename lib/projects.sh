#!/usr/bin/env bash

project_cli() {
    command_exists python3 || die "python3 is required for projects."
    python3 -I "$LIB_DIR/projects.py" "$@"
}

project_exists() {
    project_cli exists "$1" >/dev/null 2>&1
}

project_create() {
    local name="$1" info="$2" goals="$3"
    project_cli create "$name" --info "$info" --goals "$goals"
}

project_list() {
    project_cli list
}

project_show() {
    project_cli show "$1"
}

project_summary_json() {
    project_cli summary "$1"
}

project_add_step() {
    local name="$1" step="$2" goal="$3" args="${4:-}"
    if [[ -n "$args" ]]; then
        project_cli add-step "$name" "$step" --goal "$goal" --project-args "$args"
    else
        project_cli add-step "$name" "$step" --goal "$goal"
    fi
}

project_set_step() {
    local name="$1" step="$2" status="$3" note="${4:-}"
    project_cli set-step "$name" "$step" "$status" --note "$note"
}

project_active_step() {
    project_cli active-step "$1"
}

project_resume_args() {
    local name="$1"
    project_cli resume-args "$name"
}

project_record_scan() {
    local status="$1" run="$2" profile="$3" targets="$4" name="$5" step="${6:-}"
    local tmp="$run/project.json"
    [[ -n "$name" ]] || return 0
    [[ -d "$run" ]] || return 0
    XAMLTECH_PROJECT_ARGV="$(printf '%s\n' "${ORIGINAL_ARGS[@]}")" \
        project_cli record-scan "$name" --run "$run" --profile "$profile" \
        --targets "$targets" --status "$status" --step "$step" || return 0
    local tmp_file
    tmp_file="$(mktemp "$run/.project.XXXXXX")"
    if project_summary_json "$name" > "$tmp_file"; then
        mv -f "$tmp_file" "$tmp"
    else
        rm -f "$tmp_file"
    fi
}
